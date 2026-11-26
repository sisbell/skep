//! The composition's reads over the scripted board.
//!
//! The suite checks `compose`: §1.3's reads in order, each at the head,
//! nothing written; the sides whose base the board does not serve, refused
//! before any image, and more sides than one byte numbers, refused before
//! any read; the base each side's line ends at — a version begun before
//! version 1, the document's own arrangement and its text before a window
//! addressed below it, a named base checked beside the recorded ones, a
//! line the board cannot serve; a fork merged from the source the board
//! serves, its own text a window, a staged fork over its recorded base, a
//! fork's anchor; an image in parts rejoined, a sub-run value read mapped
//! to the side's V-ordinals, origins bare documents; a draft side read at
//! a position, retrying `history_busy`, the record naming the position,
//! its base read off the board, a draft staged from a daughter composing
//! over the daughter's base; and the fences — a side that changes while it
//! is read refused, a draft's recorded base moved while it is read
//! refused, a trunk member read as of a draft's named position, and a
//! board serving no `arranged_at` refused at the first fence; the dedup's
//! values read together through each side; the line rule's base text read
//! together through the head, whatever the dedup's switch, a window
//! withheld in the text that decides it refused whatever the switches,
//! naming the window and the pair's place, and one past that text never
//! read; and a removal at a line's edge asked, its gap recorded naming it
//! and verified, a window withheld in its pair's text refused naming the
//! removal's place.

use super::*;

/// §1.3's reads IN ORDER, every one AT THE HEAD (skep #1144): the
/// document's metadata, the daughter's for the base the board recorded for
/// it (skep #1113), the head's OPENING FENCE — its `doc_metadata` — then
/// the head's extent and image, the base's extent and image, the
/// daughter's extent and image, ONE VALUE READ through the head — the line
/// rule's, of the base text between the head's "big " and the daughter's
/// removal of " sat", which meet at no line's edge (skep #1176) — the
/// head's CLOSING FENCE, then the prior records by the links of the kind
/// to the daughter — a record links every side but the head — and nothing
/// written, nothing read through `/op-at`. The daughter is a published
/// version below the head and takes no fence. The result is the race
/// shape's M with its counts, key, cap and unlanded record, its `as_of`
/// the position the head's fence stood at.
#[test]
fn compose_reads_in_the_records_order_and_writes_nothing() {
    let (dialer, board, _) = open(World::race());
    let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    assert_eq!(
        dialer.ops(),
        [
            "doc_metadata",
            "doc_metadata",
            "doc_metadata",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_v",
            "doc_metadata",
            "find_links_ftt"
        ],
        "every read at the head, none rebuilding a past state"
    );
    let through: Vec<String> = dialer.frames("retrieve_v")[0]["specs"]
        .as_array()
        .expect("the read's specs")
        .iter()
        .map(|s| s["doc"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !through.is_empty() && through.iter().all(|doc| *doc == format!("{D}.2")),
        "the line rule's read, through the head: {through:?}"
    );
    assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
    let metadata: Vec<String> = dialer
        .frames("doc_metadata")
        .iter()
        .map(|f| f["doc"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        metadata,
        [D.to_string(), format!("{D}.1.1"), format!("{D}.2"), format!("{D}.2")],
        "the trunk's, the daughter's — its recorded base `D.1` ending its line on the trunk — then the head's two fences"
    );
    let docs: Vec<String> = dialer
        .frames("retrieve_doc_v_span_set")
        .iter()
        .map(|f| f["doc"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        docs,
        [format!("{D}.2"), format!("{D}.1"), format!("{D}.1.1")],
        "the head's extent, then the base's, then the daughter's"
    );
    let imaged: Vec<String> =
        dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        imaged,
        [format!("{D}.2"), format!("{D}.1"), format!("{D}.1.1")],
        "the head, the base, the daughter"
    );
    assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)], "the big cat");
    assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
    assert_eq!(merged.families, vec![Family::Own, Family::Own, Family::Own]);
    assert_eq!((merged.cap, merged.head_extent), (SHOT_RUN_CAP, 15));
    assert_eq!(
        merged.key,
        RecordKey::new(
            a(D),
            a(&format!("{D}.1")),
            [a(&format!("{D}.2")), a(&format!("{D}.1.1"))],
            []
        )
    );
    assert_eq!(merged.key, merged.record.key(), "the key is the record's own");
    assert_eq!(
        merged.key.sides,
        vec![a(&format!("{D}.1.1")), a(&format!("{D}.2"))],
        "the sides a sorted set"
    );
    assert_eq!(
        (
            merged.record.landed.clone(),
            merged.record.claims.len(),
            merged.record.replaces.clone(),
            merged.prior.clone()
        ),
        (None, 0, None, None)
    );
    assert_eq!(
        merged.record.sides.iter().map(SideAt::role).collect::<Vec<_>>(),
        [Role::Head, Role::Alternative]
    );
    assert_eq!(merged.record.to_value()["type"].as_str(), Some("merge"));
    let w = dialer.world();
    assert_eq!(w.rows.len(), 3, "nothing written");
    assert_eq!(merged.as_of, w.position);
}

/// The fence on sides whose base the board does not serve: a member of
/// another document, the bare document itself and an address within a
/// member, and a draft of another account each refuse `BaseUnknown`
/// before any `image`; two drafts refuse `TwoDrafts`. A DRAFT is read
/// before it is judged — its `doc_metadata`, for the base the board
/// records for it (skep #743) — and composes with no base named where
/// one is recorded, refusing, still before any `image`, `BaseUnknown`
/// where the board records none (a draft never staged) or where its
/// recorded base lies in another document. A FORK is read before it is
/// judged — its `doc_metadata`, for the source it was born sharing — and
/// refuses, still before any `image`: `BaseUnknown` where no `version`
/// minted it (no source) or where its source lies in another document;
/// `Unreadable` where the merger may not read the fork at all. A base
/// the caller names beside a fork side refuses `ForkBaseNamed` before
/// any read. A fork is ANOTHER ACCOUNT'S document (skep #1107): one of
/// the trunk owner's own account — the merger's staged draft, alone or
/// beside the draft side — refuses `ForkOfOwner` after the trunk's
/// metadata alone, one in `D`'s own tree refuses `BaseUnknown` before
/// any read, and a sub-account's composes, the account compared
/// exactly. (A draft or a fork begun from the bare document composes
/// over its own arrangement: `every_side_whose_line_ends_at_the_document_composes_over_it`.)
#[test]
fn a_foreign_side_or_a_side_without_a_served_base_refuses_before_any_image() {
    let mut w = World::race();
    // Another published document `Z` with a member, and three forks in
    // another account: one no `version` minted, one of `Z`'s member,
    // and one the merger may not read.
    let (unminted, of_z, hidden) = ("1.0.2.0.65", "1.0.2.0.66", "1.0.2.0.68");
    w.text(Z, 1, "hello");
    w.doc(Z, true, ACCOUNT, vec![run(Z, 1, 5)]);
    w.member(&format!("{Z}.1"), vec![run(Z, 1, 5)], None);
    w.doc(unminted, false, "1.0.2", Vec::new());
    w.fork(of_z, "1.0.2", &format!("{Z}.1"), vec![run(Z, 1, 5)]);
    w.fork(hidden, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
    w.withheld.insert(hidden.to_string());
    // Three drafts of the merger's account: `S` staged from the base
    // `D.1` with "!!!" typed at its end; one never staged, so the board
    // records no base; one staged from `Z`'s member.
    let (unstaged, of_z_draft) = ("1.0.1.0.67", "1.0.1.0.68");
    w.text(S, 1, "!!!");
    w.doc(S, false, ACCOUNT, vec![run(D, 1, 11), run(S, 1, 3)]);
    w.staged(S, &format!("{D}.1"), 11);
    w.doc(unstaged, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.doc(of_z_draft, false, ACCOUNT, vec![run(Z, 1, 5)]);
    w.staged(of_z_draft, &format!("{Z}.1"), 5);
    // A second draft of the merger's staged from `D.1`, " sat" removed,
    // and the agent space's fork of `D.1` that did the same: a
    // sub-account's document, another account's.
    let (second, agents) = ("1.0.1.0.69", "1.0.1.1.0.70");
    w.doc(second, false, ACCOUNT, vec![run(D, 1, 7)]);
    w.staged(second, &format!("{D}.1"), 11);
    w.fork(agents, "1.0.1.1", &format!("{D}.1"), vec![run(D, 1, 7)]);
    let (dialer, board, _) = open(w);
    let with =
        |sides: Vec<Side>, base: Option<Address>| Inputs { sides, base, ..race_inputs() };
    let refuses = |side: Side, base: Option<Address>, want: Refusal| {
        dialer.clear();
        assert_eq!(compose(&board, Some(&token()), &with(vec![side], base)), Err(want));
        assert!(
            !dialer.names().iter().any(|o| o == "image"),
            "no image before the refusal: {:?}",
            dialer.ops()
        );
    };
    let fork = |text: &str| Side::Fork(a(text));
    refuses(fork(unminted), None, Refusal::BaseUnknown(fork(unminted)));
    assert_eq!(
        dialer.ops(),
        ["doc_metadata", "doc_metadata"],
        "the trunk's metadata, then the fork's opening fence for its anchor, at the head, and nothing after"
    );
    assert_eq!(dialer.frames("doc_metadata")[1]["doc"], unminted);
    refuses(fork(of_z), None, Refusal::BaseUnknown(fork(of_z)));
    refuses(fork(hidden), None, Refusal::Unreadable(a(hidden)));
    refuses(
        fork(F),
        Some(a(&format!("{D}.1"))),
        Refusal::ForkBaseNamed { fork: a(F), base: a(&format!("{D}.1")) },
    );
    assert!(
        dialer.ops().is_empty(),
        "no read at all for a base named beside a fork: {:?}",
        dialer.ops()
    );
    let foreign = Side::Member(a(&format!("{Z}.1")));
    refuses(foreign.clone(), None, Refusal::BaseUnknown(foreign));
    // The bare document itself, and an address within a member, are no
    // member: refused before any read past the shape's own.
    for not_a_member in [D.to_string(), format!("{D}.1.0.1.3")] {
        let side = Side::Member(a(&not_a_member));
        refuses(side.clone(), None, Refusal::BaseUnknown(side));
        assert!(dialer.ops().is_empty(), "no read: {:?}", dialer.ops());
    }
    let other_account = Side::Draft { at: a("1.0.2.0.71"), position: None };
    refuses(
        other_account.clone(),
        Some(a(&format!("{D}.1"))),
        Refusal::BaseUnknown(other_account),
    );
    // The drafts: the staged one composes with no base named, its base
    // read off the board right after the trunk's metadata; the others
    // refuse after that read and before any image.
    let draft = |text: &str| Side::Draft { at: a(text), position: None };
    dialer.clear();
    let merged =
        compose(&board, Some(&token()), &with(vec![draft(S)], None)).expect("composed");
    assert_eq!(merged.key.base, a(&format!("{D}.1")), "the base the board records for the draft");
    assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(S, 1, 3)]);
    assert_eq!(
        dialer.frames("doc_metadata")[1]["doc"],
        S,
        "the draft's metadata, for its base: {:?}",
        dialer.ops()
    );
    refuses(draft(unstaged), None, Refusal::BaseUnknown(draft(unstaged)));
    assert_eq!(
        dialer.ops(),
        ["doc_metadata", "doc_metadata"],
        "the trunk's metadata, then the draft's opening fence for its base, at the head, and nothing after"
    );
    refuses(draft(of_z_draft), None, Refusal::BaseUnknown(draft(of_z_draft)));
    // A FORK is another account's document (skep #1107): the merger's
    // own draft `S` named as a fork refuses `ForkOfOwner` after the
    // trunk's metadata alone, and so does a second draft of the owner's
    // named as a fork beside the draft side, which `TwoDrafts` would
    // otherwise never see; a fork in `D`'s own tree refuses
    // `BaseUnknown` with no read at all; the agent space's fork, a
    // sub-account's, composes.
    refuses(fork(S), None, Refusal::ForkOfOwner { fork: a(S) });
    assert_eq!(dialer.ops(), ["doc_metadata"], "the trunk's metadata, and nothing after");
    let beside = vec![draft(S), fork(second)];
    assert_eq!(
        compose(&board, Some(&token()), &with(beside, None)),
        Err(Refusal::ForkOfOwner { fork: a(second) })
    );
    for in_tree in [D.to_string(), format!("{D}.1"), format!("{D}.1.1"), format!("{D}.1.0.1.3")] {
        refuses(fork(&in_tree), None, Refusal::BaseUnknown(fork(&in_tree)));
        assert!(dialer.ops().is_empty(), "no read: {:?}", dialer.ops());
    }
    let theirs = compose(&board, Some(&token()), &with(vec![fork(agents)], None))
        .expect("a sub-account's fork composes");
    assert_eq!(m_runs(&theirs), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)], "the big cat");
    assert_eq!(theirs.key.base, a(&format!("{D}.1")), "the fork's served source");
    let said = Refusal::ForkOfOwner { fork: a(S) }.to_string();
    assert!(said.contains("not another account's fork") && said.contains("as the draft side"), "{said}");
    let two = vec![
        Side::Draft { at: a(S), position: None },
        Side::Draft { at: a("1.0.1.0.67"), position: None },
    ];
    assert_eq!(
        compose(&board, Some(&token()), &with(two, Some(a(&format!("{D}.1"))))),
        Err(Refusal::TwoDrafts)
    );
}

/// The inputs merging the head `D.2` with `side`, no base named.
fn with_side(side: Side) -> Inputs {
    Inputs { sides: vec![side], ..race_inputs() }
}

/// The documents each `image` frame the dialer served read, in order.
fn imaged(dialer: &Scripted) -> Vec<String> {
    dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect()
}

/// A VERSION BEGUN BEFORE VERSION 1 (skep #1113): the daughter `D.1.1`,
/// a draft staged from the empty `D` and published once `D.1` stood, is
/// recorded against `D` while its address says `D.1`. The composition
/// reads the base the board recorded — ONE `doc_metadata` of the
/// daughter, at the head, right after the trunk's, the head's fences
/// around its images and values — and composes over `D`'s own
/// arrangement from before version 1, empty (`own_count` 0), reading
/// nothing of it: the head's "the fox jumps"
/// and the daughter's "the cat" are both additions at the one spot —
/// their values read through the sides that hold them, one read each, the
/// value rule
/// finding no identical bytes — ONE unsettled `order` gap, the head's
/// first by default, and "the fox" is kept (the mutant that takes the
/// daughter's address composes over `D.1` and drops it, its removal by
/// the daughter). The key and the record name `D`.
#[test]
fn a_version_begun_before_version_1_composes_over_the_documents_own_arrangement() {
    let (dialer, board, _) = open(World::begun_before_version_1());
    let merged =
        compose(&board, Some(&token()), &with_side(Side::Member(a(&format!("{D}.1.1")))))
            .expect("composed");
    assert_eq!(
        dialer.ops(),
        [
            "doc_metadata",
            "doc_metadata",
            "doc_metadata",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_v",
            "retrieve_v",
            "doc_metadata",
            "find_links_ftt"
        ],
        "the trunk's metadata, the daughter's for its recorded base, the head's fence, the head and the daughter and their values, the head's fence again — nothing of `D`, all at the head"
    );
    let delivered: Vec<String> = dialer
        .frames("retrieve_v")
        .iter()
        .map(|f| f["specs"][0]["doc"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        delivered,
        [format!("{D}.2"), format!("{D}.1.1")],
        "each addition read through the side holding it"
    );
    assert_eq!(dialer.frames("doc_metadata")[1]["doc"], format!("{D}.1.1"));
    assert_eq!(
        imaged(&dialer),
        [format!("{D}.2"), format!("{D}.1.1")],
        "the head and the daughter alone"
    );
    assert_eq!(
        (merged.key.base.clone(), merged.record.base.clone()),
        (a(D), a(D)),
        "the base the board recorded"
    );
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 13), run(D, 20, 7)],
        "the fox jumps, then the cat: both kept"
    );
    assert_eq!(
        merged.composed.gaps.iter().map(|g| (g.kind, g.settled)).collect::<Vec<_>>(),
        vec![(GapKind::Order, false)],
        "both texts at the one spot"
    );
    assert_eq!(merged.composed.counts, RunCounts { a: 1, b: 1, m: 2 });
}

/// THE DOCUMENT'S OWN TEXT LEADS a window onto a document addressed
/// below it, over any base (skep #1115; R1). Over `D`'s own arrangement,
/// empty: the daughter `D.1.2`, recorded against `D`, is a window onto
/// `DOC1`'s "an owl" — the head's "the fox jumps" first and the window
/// after it at the one spot, an unsettled `order` gap. Over the member
/// `D.1`, a window onto `Z` and none of `D`'s text: the head's own
/// " jumps" after it leads the daughter's window onto `DOC1` the same
/// way. The chain the composition reads is the document's, never the
/// base's address nor the head's.
#[test]
fn the_documents_own_text_comes_before_a_window_addressed_below_it_over_any_base() {
    assert!(a(DOC1) < a(D), "the premise: `DOC1` is addressed below `D`");
    let order = |merged: &Merged| -> Vec<(GapKind, bool, Placement)> {
        merged.composed.gaps.iter().map(|g| (g.kind, g.settled, g.placed.clone())).collect()
    };
    let unsettled = vec![(GapKind::Order, false, Placement::Order(vec![SideIx(0), SideIx(1)]))];
    let mut w = World::begun_before_version_1();
    w.text(DOC1, 1, "an owl");
    w.doc(DOC1, true, ACCOUNT, vec![run(DOC1, 1, 6)]);
    w.member(&format!("{D}.1.2"), vec![run(DOC1, 1, 6)], Some(0));
    w.bare_based(&format!("{D}.1.2"));
    let (_dialer, board, _) = open(w);
    let merged =
        compose(&board, Some(&token()), &with_side(Side::Member(a(&format!("{D}.1.2")))))
            .expect("composed");
    assert_eq!(merged.key.base, a(D), "the document's own arrangement, empty");
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 13), run(DOC1, 1, 6)],
        "the fox jumps, then an owl"
    );
    assert_eq!(merged.families, vec![Family::Own, Family::Window]);
    assert_eq!(order(&merged), unsettled, "both texts at the one spot");
    let mut w = World::new();
    w.text(Z, 1, "hello");
    w.text(D, 1, " jumps");
    w.text(DOC1, 1, "an owl");
    w.doc(Z, true, ACCOUNT, vec![run(Z, 1, 5)]);
    w.doc(DOC1, true, ACCOUNT, vec![run(DOC1, 1, 6)]);
    let head = vec![run(Z, 1, 5), run(D, 1, 6)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), vec![run(Z, 1, 5)], None);
    w.member(&format!("{D}.2"), head, Some(5));
    w.member(&format!("{D}.1.1"), vec![run(Z, 1, 5), run(DOC1, 1, 6)], Some(5));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let (_dialer, board, _) = open(w);
    let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    assert_eq!(merged.key.base, a(&format!("{D}.1")), "a member holding none of `D`'s text");
    assert_eq!(
        m_runs(&merged),
        vec![run(Z, 1, 5), run(D, 1, 6), run(DOC1, 1, 6)],
        "hello jumps, then an owl"
    );
    assert_eq!(order(&merged), unsettled, "both additions after the window");
}

/// EVERY LINE THAT ENDS AT THE DOCUMENT composes over it (skep #1113),
/// each `D`'s empty own arrangement, nothing of `D` imaged: a member
/// under the bare-based daughter, `D.1.1.1`, its line two hops read in
/// order; the draft whose publication minted that daughter, its
/// recorded base moved there; a fork whose source is the daughter; a
/// draft staged from `D` itself and a fork of `D` itself, still
/// unpublished with `D.1` standing, each anchored at the document; and
/// the bare-based daughter beside `D.2.1`, whose line ends at `D.2` —
/// a line ending at `D` makes the base `D` whatever the others. `D.2.1`
/// alone composes over `D.2`.
#[test]
fn every_side_whose_line_ends_at_the_document_composes_over_it() {
    let mut w = World::begun_before_version_1();
    let (published_from, staged_bare) = ("1.0.1.0.70", S);
    let (fork_of_daughter, fork_of_bare) = (F, "1.0.2.0.70");
    w.text(D, 40, " now");
    w.text(staged_bare, 1, "the owl");
    w.text(fork_of_bare, 1, "a lynx");
    w.member(&format!("{D}.1.1.1"), vec![run(D, 20, 7), run(D, 40, 4)], Some(7));
    w.doc(published_from, false, ACCOUNT, vec![run(D, 20, 7)]);
    w.staged(published_from, &format!("{D}.1.1"), 7);
    w.doc(staged_bare, false, ACCOUNT, vec![run(staged_bare, 1, 7)]);
    w.staged(staged_bare, D, 0);
    w.fork(fork_of_daughter, "1.0.2", &format!("{D}.1.1"), vec![run(D, 20, 7)]);
    w.fork(fork_of_bare, "1.0.2", D, vec![run(fork_of_bare, 1, 6)]);
    let (dialer, board, _) = open(w);
    let sides = [
        Side::Member(a(&format!("{D}.1.1.1"))),
        Side::Draft { at: a(published_from), position: None },
        Side::Fork(a(fork_of_daughter)),
        Side::Draft { at: a(staged_bare), position: None },
        Side::Fork(a(fork_of_bare)),
    ];
    for side in sides {
        dialer.clear();
        let merged = compose(&board, Some(&token()), &with_side(side.clone()))
            .unwrap_or_else(|e| panic!("{side:?}: {e:?}"));
        assert_eq!(merged.key.base, a(D), "{side:?}");
        assert!(
            !imaged(&dialer).contains(&D.to_string()),
            "{side:?}: nothing of `D` imaged: {:?}",
            dialer.ops()
        );
        let met: Vec<String> = dialer
            .frames("doc_metadata")
            .iter()
            .map(|f| f["doc"].as_str().unwrap().to_string())
            .collect();
        let mut line: Vec<String> = match &side {
            Side::Member(m) => vec![D.to_string(), m.to_string(), format!("{D}.1.1")],
            Side::Draft { at, .. } if at == &a(published_from) => {
                vec![D.to_string(), at.to_string(), format!("{D}.1.1")]
            }
            Side::Fork(f) if f == &a(fork_of_daughter) => {
                vec![D.to_string(), f.to_string(), format!("{D}.1.1")]
            }
            other => vec![D.to_string(), other.address().to_string()],
        };
        // The head's opening fence after the lines; then the closing
        // fences, a draft's or a fork's before the head's — a member
        // below the head takes none.
        let head = format!("{D}.2");
        line.push(head.clone());
        if !matches!(side, Side::Member(_)) {
            line.push(side.address().to_string());
        }
        line.push(head);
        assert_eq!(
            met, line,
            "{side:?}: the trunk's, the side's own, each hop of its line, then the fences"
        );
    }
    let (bare_based, ordinary) =
        (Side::Member(a(&format!("{D}.1.1"))), Side::Member(a(&format!("{D}.2.1"))));
    for sides in [vec![bare_based.clone(), ordinary.clone()], vec![ordinary, bare_based]] {
        let merged =
            compose(&board, Some(&token()), &Inputs { sides: sides.clone(), ..race_inputs() })
                .unwrap_or_else(|e| panic!("{sides:?}: {e:?}"));
        assert_eq!(
            merged.key.base,
            a(D),
            "{sides:?}: one line ends at the document, whichever side comes later"
        );
    }
    let ordinary =
        compose(&board, Some(&token()), &with_side(Side::Member(a(&format!("{D}.2.1")))))
            .expect("composed");
    assert_eq!(ordinary.key.base, a(&format!("{D}.2")), "recorded against its address parent");
    assert_eq!(
        m_runs(&ordinary),
        vec![run(D, 1, 7), run(D, 30, 5)],
        "the fox runs: the daughter's removal of \" jumps\" stands"
    );
}

/// THE DOCUMENT'S OWN ARRANGEMENT read where it holds words (PUB-2.66;
/// the arrangement suite's shape, `stage.rs`'s): `D` held "abcz" before
/// its first version, `own_count` 4; version 1 is "abc"; the daughter
/// `D.1.1`, begun from `D` and recorded against it, is "abcwz". The base
/// is read ONCE, `image` with `own`, at the head, and M is
/// "abcw": the head's removal of "z" stands and the daughter's "w" goes
/// beside the surviving "c", an `anchor` gap the rules settle — where
/// over `D.1`, as the address would have it, "z" comes back as the
/// daughter's addition, and over `D` floated to its head (an image with
/// no `own`) the same. Landed, its record names `D`, and `verify` asks
/// the join's `compare` with the base region carrying `own` and answers
/// `Equal`.
#[test]
fn a_documents_own_arrangement_is_read_with_own_where_its_count_is_above_0() {
    let mut w = World::new();
    w.text(D, 1, "abcz");
    w.text(D, 5, "w");
    w.doc(D, true, ACCOUNT, vec![run(D, 1, 3)]);
    w.pre_chain.insert(D.to_string(), vec![run(D, 1, 4)]);
    w.member(&format!("{D}.1"), vec![run(D, 1, 3)], None);
    w.member(&format!("{D}.1.1"), vec![run(D, 1, 3), run(D, 5, 1), run(D, 4, 1)], Some(4));
    w.bare_based(&format!("{D}.1.1"));
    w.trunk_head.insert(D.to_string(), format!("{D}.1"));
    let (dialer, board, signer) = open(w);
    let inputs = Inputs {
        head: a(&format!("{D}.1")),
        ..with_side(Side::Member(a(&format!("{D}.1.1"))))
    };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    let of_d: Vec<Value> = dialer.frames("image").into_iter().filter(|f| f["d"] == D).collect();
    assert_eq!(
        of_d,
        vec![frames::image_own(D, 1, 4)],
        "the document's own arrangement, read once with `own`"
    );
    assert!(
        dialer.ops().iter().all(|o| !o.starts_with("at:")),
        "at the head, no past state rebuilt: {:?}",
        dialer.ops()
    );
    assert_eq!(merged.key.base, a(D));
    assert_eq!(m_runs(&merged), vec![run(D, 1, 3), run(D, 5, 1)], "abcw");
    assert_eq!(
        merged.composed.gaps.iter().map(|g| (g.kind, g.settled)).collect::<Vec<_>>(),
        vec![(GapKind::Anchor, true)],
        "the daughter's `w` beside the surviving `c`"
    );
    let session = sign_in(&board, &signer);
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!(record.base, a(D));
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record).expect("verified"), Verdict::Equal);
    let compared = dialer.frames("compare");
    assert!(
        !compared.is_empty()
            && compared.iter().all(|f| f["rho1"] == json!([frames::region_own(D, 1, 4)])),
        "the oracle reads the base as it was imaged: {compared:?}"
    );
}

/// THE LINE THE BOARD CANNOT SERVE refuses before any `image` (skep
/// #1113): on a board serving no `own_count` — an older board — a side
/// whose line ends at `D` is `BareSource`, naming the side, `D` and the
/// hop whose recorded base `D` is (none for a draft staged from `D`
/// itself); a hop serving neither `shot_base` nor `source` is
/// `HopUnrecorded` naming it, its address never taken as its parent; a
/// hop whose recorded base its address contradicts is the board's fault,
/// faced. A daughter `D.1.1` recorded against `D.1`, its address
/// parent, composes over `D.1`.
#[test]
fn a_line_the_board_cannot_serve_refuses_before_any_image() {
    let mut w = World::begun_before_version_1();
    w.text(D, 40, " now");
    w.member(&format!("{D}.1.1.1"), vec![run(D, 20, 7), run(D, 40, 4)], Some(7));
    w.text(S, 1, "the owl");
    w.doc(S, false, ACCOUNT, vec![run(S, 1, 7)]);
    w.staged(S, D, 0);
    w.no_own_count = true;
    let (dialer, board, _) = open(w);
    let daughter = a(&format!("{D}.1.1"));
    let refused = |side: Side| -> Refusal {
        dialer.clear();
        let err = compose(&board, Some(&token()), &with_side(side)).expect_err("refused");
        assert!(imaged(&dialer).is_empty(), "no image before the refusal: {:?}", dialer.ops());
        err
    };
    let member = Side::Member(daughter.clone());
    assert_eq!(
        refused(member.clone()),
        Refusal::BareSource { side: member.clone(), source: a(D), hop: Some(daughter.clone()) }
    );
    let under = Side::Member(a(&format!("{D}.1.1.1")));
    assert_eq!(
        refused(under.clone()),
        Refusal::BareSource { side: under, source: a(D), hop: Some(daughter.clone()) }
    );
    let draft = Side::Draft { at: a(S), position: None };
    assert_eq!(
        refused(draft.clone()),
        Refusal::BareSource { side: draft, source: a(D), hop: None }
    );
    dialer.world().no_own_count = false;
    dialer.world().docs.get_mut(&daughter.to_string()).unwrap().shot_base = None;
    assert_eq!(
        refused(member.clone()),
        Refusal::HopUnrecorded { side: member.clone(), hop: daughter.clone() }
    );
    dialer.world().docs.get_mut(&daughter.to_string()).unwrap().shot_base =
        Some(format!("{D}.2"));
    let Refusal::Halt(Halt::Halt(face)) = refused(member.clone()) else { panic!("faced") };
    assert!(
        face.state.contains(&format!("{D}.2")) && face.act.contains("board fault"),
        "{face}"
    );
    dialer.world().docs.get_mut(&daughter.to_string()).unwrap().shot_base =
        Some(format!("{D}.1"));
    dialer.clear();
    let merged = compose(&board, Some(&token()), &with_side(member)).expect("composed");
    assert_eq!(merged.key.base, a(&format!("{D}.1")), "recorded against its address parent");
}

/// A NAMED BASE IS CHECKED BESIDE MEMBER SIDES (skep #1113): naming
/// `D.1` — the base the bare-based daughter's address says — beside it
/// is refused `NamedBaseDisagrees` before any `image`; naming `D`
/// composes. Landed, its record verifies `Equal`; the same record over
/// `D.1`, as a build deriving the base from the address wrote it, is
/// refused the same at `verify`, never answered `Equal`.
#[test]
fn a_named_base_beside_member_sides_is_checked_against_the_recorded_bases() {
    let (dialer, board, signer) = open(World::begun_before_version_1());
    let daughter = Side::Member(a(&format!("{D}.1.1")));
    let named = |base: &str| Inputs { base: Some(a(base)), ..with_side(daughter.clone()) };
    let by_address = a(&format!("{D}.1"));
    assert_eq!(
        compose(&board, Some(&token()), &named(&format!("{D}.1"))),
        Err(Refusal::NamedBaseDisagrees { named: by_address.clone(), served: a(D) })
    );
    assert!(imaged(&dialer).is_empty(), "nothing imaged: {:?}", dialer.ops());
    let merged = compose(&board, Some(&token()), &named(D)).expect("composed");
    assert_eq!(merged.key.base, a(D));
    let session = sign_in(&board, &signer);
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    let over_the_address = Record { base: by_address.clone(), ..record };
    dialer.clear();
    assert_eq!(
        verify(&board, Some(&token()), &over_the_address),
        Err(Refusal::NamedBaseDisagrees { named: by_address, served: a(D) })
    );
    assert!(imaged(&dialer).is_empty(), "nothing imaged: {:?}", dialer.ops());
}

/// MORE SIDES THAN ONE BYTE NUMBERS REFUSE BEFORE ANY READ (skep #792):
/// every list the walk is given is numbered by its one-byte `SideIx`,
/// the head's 0 and each side's its place after it, so a 256th side
/// would be read and reported as the head. Two hundred and fifty-six
/// sides besides the head are refused by name with no frame sent, and
/// so is a record naming as many at `verify`; two hundred and fifty-five
/// pass the count, a foreign member among them refused `BaseUnknown`
/// before any read.
#[test]
fn more_sides_than_one_byte_numbers_refuse_before_any_read() {
    let (dialer, board, _) = open(World::race());
    let daughters = |n: usize| -> Vec<Side> {
        (1..=n).map(|k| Side::Member(a(&format!("{D}.1.{k}")))).collect()
    };
    let refused = |err: Refusal| {
        let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
        assert!(
            face.state.contains(&format!("{} sides besides the head", MAX_SIDES + 1))
                && face.state.contains(&format!("the {MAX_SIDES} ")),
            "{face}"
        );
        assert!(
            face.act.contains("nothing was read or written")
                && !face.act.contains("fault in this library"),
            "{face}"
        );
        assert!(dialer.ops().is_empty(), "no frame before the refusal: {:?}", dialer.ops());
    };
    dialer.clear();
    let past = Inputs { sides: daughters(MAX_SIDES + 1), ..race_inputs() };
    refused(compose(&board, Some(&token()), &past).expect_err("refused"));
    let mut record = compose(&board, Some(&token()), &race_inputs()).expect("composed").record;
    record
        .sides
        .extend(daughters(MAX_SIDES + 1).iter().skip(1).map(|side| SideAt::of(side, 0, None)));
    dialer.clear();
    refused(verify(&board, Some(&token()), &record).expect_err("refused"));
    let foreign = Side::Member(a(&format!("{Z}.1")));
    let mut sides = daughters(MAX_SIDES - 1);
    sides.push(foreign.clone());
    dialer.clear();
    assert_eq!(
        compose(&board, Some(&token()), &Inputs { sides, ..race_inputs() }),
        Err(Refusal::BaseUnknown(foreign))
    );
    assert!(dialer.ops().is_empty(), "{:?}", dialer.ops());
}

/// CASE (j): a cross-owner fork of a PUBLISHED version merges from the
/// source the board serves for it. The fork `F`, another account's
/// private document minted by `version` off the base `D.1` ("the cat
/// sat"), has removed " sat"; the head added "big ". The reads, in
/// order, each at the head: the trunk's metadata, THE FORK'S METADATA for
/// its `source` — its opening fence — the head's opening fence, the
/// head's extent and image, the base's extent and image — the base `D.1`,
/// derived from the source and never named — the fork's extent and image,
/// the line rule's one value read of the base text between "big " and the
/// fork's removal (skep #1176), the fork's and the head's closing fences,
/// the prior records by the links of the kind to the fork, a record
/// linking every side but the head. M is
/// the race shape's "the big cat", the fork's role `fork`, the merge lands
/// as the trunk's
/// next member, and `verify` recomputes its record against the source
/// the board serves.
#[test]
fn case_j_a_fork_of_a_published_version_merges_from_the_source_the_board_serves() {
    let mut w = World::race();
    w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
    let (dialer, board, signer) = open(w);
    let inputs = Inputs { sides: vec![Side::Fork(a(F))], ..race_inputs() };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    assert_eq!(
        dialer.ops(),
        [
            "doc_metadata",
            "doc_metadata",
            "doc_metadata",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_v",
            "doc_metadata",
            "doc_metadata",
            "find_links_ftt"
        ]
    );
    let metadata: Vec<String> = dialer
        .frames("doc_metadata")
        .iter()
        .map(|f| f["doc"].as_str().unwrap().to_string())
        .collect();
    let head = format!("{D}.2");
    assert_eq!(
        metadata,
        [D.to_string(), F.to_string(), head.clone(), F.to_string(), head],
        "the trunk's, the fork's and the head's opening fences, then their closing fences"
    );
    let imaged: Vec<String> =
        dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        imaged,
        [format!("{D}.2"), format!("{D}.1"), F.to_string()],
        "the head, the base the source names, the fork"
    );
    assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)], "the big cat");
    assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
    assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
    assert_eq!(merged.families, vec![Family::Own, Family::Own, Family::Own]);
    assert_eq!(merged.key.base, a(&format!("{D}.1")), "the base is the fork's source");
    assert_eq!(merged.key.sides, vec![a(&format!("{D}.2")), a(F)]);
    assert_eq!(
        merged.record.sides.iter().map(SideAt::role).collect::<Vec<_>>(),
        [Role::Head, Role::Fork]
    );
    assert_eq!(merged.record.base, a(&format!("{D}.1")));
    assert_eq!(dialer.world().rows.len(), 4, "nothing written");
    // LANDED as the shot: the fork's runs are all the document's own, so
    // nothing is windowed, and the member is the trunk's next.
    let session = sign_in(&board, &signer);
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    let Landed::Member { address, record: link, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(address.to_string(), format!("{D}.3"));
    let member = dialer.world().docs.get(&format!("{D}.3")).unwrap().clone();
    assert_eq!(member.runs, vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)]);
    // The record names the fork's base — the served source — and
    // `verify` re-reads it off the board and recomputes M.
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!(record.base, a(&format!("{D}.1")));
    assert_eq!(record.link.as_ref(), Some(link));
    assert_eq!(verify(&board, Some(&token()), &record).expect("verified"), Verdict::Equal);
}

/// Case (j) with the fork's OWN text: the fork typed "fat " where the
/// head typed "big ", both at `D·4|D·5` — an `order` gap, unsettled, as
/// between two members (§9 (b)) — and the fork's fresh run is a WINDOW
/// onto the fork in M: the owner's shot keeps it by reference, and
/// `show_origin` names the forker for those bytes.
#[test]
fn a_forks_own_text_is_a_window_in_the_merge() {
    let mut w = World::race();
    let f2 = "1.0.2.0.70";
    w.text(f2, 1, "fat ");
    w.fork(f2, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 4), run(f2, 1, 4), run(D, 5, 7)]);
    let (_dialer, board, _) = open(w);
    let inputs = Inputs { sides: vec![Side::Fork(a(f2))], ..race_inputs() };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 4), run(D, 12, 4), run(f2, 1, 4), run(D, 5, 7)],
        "the big fat cat sat"
    );
    assert_eq!(
        merged.families,
        vec![Family::Own, Family::Own, Family::Window, Family::Own],
        "the fork's fresh text is a window onto the fork"
    );
    assert_eq!(
        merged.composed.gaps.iter().map(|g| (g.kind, g.settled)).collect::<Vec<_>>(),
        vec![(GapKind::Order, false)]
    );
    assert_eq!(merged.key.base, a(&format!("{D}.1")));
}

/// A STAGED FORK STANDS WHERE THE BOARD RECORDS IT (the owner's ruling
/// of 2026-11-19; skep #1106): another account's draft `Y`, staged from
/// `D.1` — its base and its `source` `D.1` — and landed into once `D.2`
/// stood, the landing moving its recorded base to `D.2` and keeping its
/// source, holds `D.2`'s "the big cat sat" and "!!!" of its own; the
/// head `D.3` has dropped "big ". Composed as a fork, its anchor is the
/// base the board records, read off the fork's ONE `doc_metadata`: the
/// base is `D.2`, the head's removal of "big " stands and the fork's
/// "!!!" is a window onto it — over its source `D.1`, "big " would come
/// back as the fork's own addition (the mutant that reads the source
/// first). Landed in a fresh draft, its record verifies `Equal`.
#[test]
fn a_staged_fork_composes_over_the_base_the_board_records_never_its_source() {
    let y = "1.0.2.0.72";
    let (v1, v2, v3) = (format!("{D}.1"), format!("{D}.2"), format!("{D}.3"));
    let mut w = World::race();
    w.text(y, 1, "!!!");
    w.doc(y, false, "1.0.2", vec![run(D, 1, 11), run(y, 1, 3)]);
    w.staged(y, &v1, 11);
    // The landing into `Y` once `D.2` stood: its words M, its base moved
    // to the head at the landing's commit, its source kept.
    let landed = w.commit("set_arrangement", vec![y.to_string()]);
    let theirs = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(y, 1, 3)];
    let fork = w.docs.get_mut(y).unwrap();
    fork.runs = theirs.clone();
    fork.history.insert(landed, theirs);
    fork.staged.insert(landed, (v2.clone(), 15));
    // The head `D.3`, "big " dropped.
    w.member(&v3, vec![run(D, 1, 11)], Some(15));
    w.trunk_head.insert(D.to_string(), v3.clone());
    let (dialer, board, signer) = open(w);
    let Answer::Document(meta) =
        board.op(Some(&token()), &frames::doc_metadata(y)).expect("the read")
    else {
        panic!("the session stands")
    };
    assert_eq!(
        (meta["base"].as_str(), meta["source"].as_str()),
        (Some(v2.as_str()), Some(v1.as_str())),
        "the premise — the landing moved the base and kept the source: {meta}"
    );
    dialer.clear();
    let inputs = Inputs { head: a(&v3), sides: vec![Side::Fork(a(y))], ..race_inputs() };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    let metadata: Vec<String> = dialer
        .frames("doc_metadata")
        .iter()
        .map(|f| f["doc"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        metadata,
        [D.to_string(), y.to_string(), v3.clone(), y.to_string(), v3.clone()],
        "the trunk's, the fork's opening fence — its one read for its anchor — and the head's, then their closing fences"
    );
    assert_eq!(
        merged.key.base,
        a(&v2),
        "the base the board records for the fork, never its source"
    );
    assert_eq!(merged.record.base, a(&v2));
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 11), run(y, 1, 3)],
        "the cat sat!!!: the head's removal stands"
    );
    assert_eq!(
        merged.families,
        vec![Family::Own, Family::Window],
        "the fork's own words a window onto it"
    );
    // LANDED in a fresh draft: its record verifies against the fork's
    // recorded base, which nothing has moved since.
    let session = sign_in(&board, &signer);
    land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!(record.base, a(&v2));
    assert_eq!(verify(&board, Some(&token()), &record).expect("verified"), Verdict::Equal);
}

/// A FORK's ANCHOR IS ITS RECORDED BASE, ELSE ITS SOURCE, EACH IN THE
/// DOCUMENT's CHAIN (skep #1106), read off the fork's one `doc_metadata`.
/// Another account's ALTERNATIVE `X2` — staged from its own draft `X1`,
/// itself staged from `D.1`, so its `source` is `X1` and its recorded
/// base the `D.1` it inherited — composes over `D.1`, nothing of `X1`
/// read (the mutant that reads the source first refuses it); a fork a
/// `version` minted, its source `D.1` and no base, composes over its
/// source. Refused exactly `BaseUnknown` with no image read: a fork
/// staged from `D.1` whose base its publication as an edition of its
/// own moved to that edition's first member — its base never passed
/// over for the source in the chain (the source-first mutant composes
/// it) — and one staged from another document's member, its base and
/// its source both there (the mutant that takes the anchor unchecked
/// walks either line, `HopUnrecorded`).
#[test]
fn a_forks_anchor_is_its_recorded_base_else_its_source_each_in_the_documents_chain() {
    let v1 = format!("{D}.1");
    let (x1, x2, minted) = ("1.0.2.0.72", "1.0.2.0.73", "1.0.2.0.74");
    let (published, edition, of_z) = ("1.0.2.0.75", "1.0.2.0.76", "1.0.2.0.77");
    let mut w = World::race();
    w.doc(x1, false, "1.0.2", vec![run(D, 1, 7)]);
    w.staged(x1, &v1, 11);
    w.doc(x2, false, "1.0.2", vec![run(D, 1, 7)]);
    w.staged(x2, &v1, 11);
    w.docs.get_mut(x2).unwrap().source = Some(x1.to_string());
    w.fork(minted, "1.0.2", &v1, vec![run(D, 1, 7)]);
    // Staged from `D.1`, then published as an edition of its own, its
    // base moved at the shot to the edition's first member.
    w.doc(published, false, "1.0.2", vec![run(D, 1, 7)]);
    w.staged(published, &v1, 11);
    w.doc(edition, true, "1.0.2", vec![run(D, 1, 7)]);
    w.member(&format!("{edition}.1"), vec![run(D, 1, 7)], None);
    let shot = w.position;
    w.docs.get_mut(published).unwrap().staged.insert(shot, (format!("{edition}.1"), 7));
    w.text(Z, 1, "hello");
    w.doc(Z, true, ACCOUNT, vec![run(Z, 1, 5)]);
    w.member(&format!("{Z}.1"), vec![run(Z, 1, 5)], None);
    w.doc(of_z, false, "1.0.2", vec![run(Z, 1, 5)]);
    w.staged(of_z, &format!("{Z}.1"), 5);
    let (dialer, board, _) = open(w);
    let fork = |text: &str| Side::Fork(a(text));
    let the_big_cat = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)];
    let merged = compose(&board, Some(&token()), &with_side(fork(x2)))
        .expect("the alternative composes");
    assert_eq!(merged.key.base, a(&v1), "the base the alternative inherited");
    assert_eq!(m_runs(&merged), the_big_cat);
    let metadata: Vec<String> = dialer
        .frames("doc_metadata")
        .iter()
        .map(|f| f["doc"].as_str().unwrap().to_string())
        .collect();
    let head = format!("{D}.2");
    assert_eq!(
        metadata,
        [D.to_string(), x2.to_string(), head.clone(), x2.to_string(), head],
        "the trunk's, the alternative's and the head's fences: nothing of its source read"
    );
    let merged = compose(&board, Some(&token()), &with_side(fork(minted)))
        .expect("the version's fork composes");
    assert_eq!(merged.key.base, a(&v1), "a fork with no recorded base stands on its source");
    assert_eq!(m_runs(&merged), the_big_cat);
    for refused in [published, of_z] {
        dialer.clear();
        assert_eq!(
            compose(&board, Some(&token()), &with_side(fork(refused))),
            Err(Refusal::BaseUnknown(fork(refused))),
            "{refused}"
        );
        assert_eq!(
            dialer.ops(),
            ["doc_metadata", "doc_metadata"],
            "{refused}: the trunk's and the fork's opening fence, nothing imaged"
        );
    }
}

/// **`image` in pages.** A head of three runs on a board whose page is two is
/// answered its first two and where the rest begins, and read on from
/// there with the go-on sent back whole — two frames, each answered, the
/// second the rest of the span from the reach of the page's last run, no
/// run cut and none joined — so `counts.a` is 3 and M is the same list.
#[test]
fn an_image_past_the_boards_page_is_read_page_by_page_no_run_cut() {
    let (dialer, board, _) = open(World::race());
    dialer.world().image_cap = 2;
    let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    let frames: Vec<Value> = dialer.frames("image").into_iter().filter(|f| f["d"] == format!("{D}.2")).collect();
    let head: Vec<(u64, u64)> = frames.iter().map(|f| span(&f["region"][0])).collect();
    assert_eq!(head, [(1, 15), (9, 7)], "the whole region, then the rest from the page's reach");
    assert!(frames[0].get("cur").is_none(), "a first page carries no go-on");
    assert_eq!(frames[1]["cur"]["at"], "9", "the continuation sends the go-on back: {}", frames[1]);
    assert_eq!(frames[1]["cur"]["surface"], format!("{D}.2"));
    assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
    assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)]);
}

/// **The reader reads a long document whole**, a page a frame and no frame
/// more: a draft of 5,000 runs is two `image` frames and one of 12,289
/// four, each the rest of the span from where the page before it ended,
/// none of a halved width — at the head, as of a position through
/// `/op-at`, and of the draft's own arrangement, sent with `own` on every
/// page; the image holds every run at its own ordinal, and its extent is
/// the extent read (the mutant that takes the first page for the image
/// answers 4,096 runs under an extent of 5,000).
#[test]
fn the_reader_images_a_long_document_whole_a_page_a_frame() {
    for (count, pages) in [(5_000u64, 2u64), (12_289, 4)] {
        let long: Vec<Run> = (1..=count).map(|k| run(D, 2 * k, 1)).collect();
        let mut world = World::new();
        world.doc(S, false, ACCOUNT, long.clone());
        let then = world.position;
        world.change(S, vec![run(D, 1, 3)]);
        world.change(S, long.clone());
        let (dialer, board, _) = open(world);
        let token = token();
        let reader = Reader::new(&board, Some(&token), OnEnd::Rerun);
        let spans = |dialer: &Scripted| -> Vec<(u64, u64)> { dialer.frames("image").iter().map(|f| span(&f["region"][0])).collect() };
        let expected: Vec<(u64, u64)> = (0..pages).map(|page| (1 + page * 4_096, count - page * 4_096)).collect();
        let whole = |extent: u64, runs: &[crate::board::IRun]| {
            assert_eq!((extent, runs.len() as u64), (count, count));
            assert!(runs.iter().enumerate().all(|(k, r)| (r.ordinal, r.first, r.width) == (k as u64 + 1, 2 * (k as u64 + 1), 1)), "every run at its own ordinal");
        };
        // At the head.
        let at_head = reader.imaged(&a(S), None).expect("imaged at the head");
        whole(at_head.extent, &at_head.runs);
        assert_eq!(spans(&dialer), expected, "{count} runs: ⌈R ÷ 4,096⌉ frames, each the rest of the span");
        assert!(dialer.positions("image").is_empty() && dialer.frames("image")[1..].iter().all(|f| f["cur"]["surface"] == S));
        // As of a position: every page through `/op-at` there.
        dialer.clear();
        let past = reader.imaged(&a(S), Some(then)).expect("imaged at a position");
        whole(past.extent, &past.runs);
        assert_eq!((spans(&dialer), dialer.positions("image")), (expected.clone(), vec![then; pages as usize]));
        // Its own arrangement: `own` on every page.
        dialer.clear();
        let own = reader.imaged_own(&a(S), None, count).expect("its own arrangement imaged");
        whole(own.extent, &own.runs);
        assert!(dialer.frames("image").len() as u64 == pages && dialer.frames("image").iter().all(|f| f["own"] == true));
    }
}

/// **A draft written under the reader.** A continuation refused `page_moved` is
/// begun again from the first page and the new state answered whole; and a
/// draft that moves at every reading the bound allows is read once more as
/// of the last first page's position, every page through `/op-at` — the
/// frames at a position counted, and none at the head after them.
#[test]
fn a_moved_draft_is_read_again_and_past_the_bound_at_one_position() {
    let long: Vec<Run> = (1..=5_000u64).map(|k| run(D, 2 * k, 1)).collect();
    let mut world = World::new();
    world.doc(S, false, ACCOUNT, long);
    let (dialer, board, _) = open(world);
    let token = token();
    let reader = Reader::new(&board, Some(&token), OnEnd::Rerun);
    dialer.world().page_moved = 1;
    assert_eq!(reader.imaged(&a(S), None).expect("read again").runs.len(), 5_000);
    assert_eq!(dialer.names().iter().filter(|n| *n == "image").count(), 4, "the first page and its refused continuation, then both pages again");
    assert!(dialer.positions("image").is_empty(), "one restart, at the head");
    dialer.clear();
    dialer.world().page_moved = PAGE_RESTARTS + 1;
    let head = dialer.world().position;
    assert_eq!(reader.imaged(&a(S), None).expect("read at a position").runs.len(), 5_000);
    let at_head = dialer.ops().iter().filter(|o| *o == "image").count() as u32;
    assert_eq!(at_head, 2 * (PAGE_RESTARTS + 1), "the first reading and the bound's restarts, each refused at its second page");
    assert_eq!(dialer.positions("image"), [head, head], "then every page at the position the last first page stood at");
    assert_eq!(dialer.ops().iter().rev().take(2).filter(|o| *o == "at:image").count(), 2, "and nothing at the head after them");
}

/// A SUB-RUN value read is mapped to the side's own V-ordinals (the
/// fragment model): with the retype normalization on, the base bytes a
/// side retyped are read through the other side's copy as the fragments
/// of that side's runs — `D·5` at V 5 of one run, `D·6–7` at V 7 of the
/// next — in ONE read of that member at the head, a spec a fragment, and
/// the retyped bytes at the retyping side's V 5.
#[test]
fn a_sub_run_value_read_is_mapped_to_the_sides_v_ordinals() {
    let mut w = World::new();
    w.text(D, 1, "the cat sat");
    w.text(D, 12, "cat");
    w.text(D, 16, "-");
    let head = vec![run(D, 1, 4), run(D, 12, 3), run(D, 8, 4)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
    w.member(&format!("{D}.2"), head, Some(11));
    w.member(&format!("{D}.1.1"), vec![run(D, 1, 5), run(D, 16, 1), run(D, 6, 6)], Some(11));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let (dialer, board, _) = open(w);
    let inputs =
        Inputs { options: Options { retype: true, ..Options::default() }, ..race_inputs() };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 5), run(D, 16, 1), run(D, 6, 6)],
        "the c-at sat: the base identity kept"
    );
    let reads: Vec<Vec<(String, u64, u64)>> = dialer
        .frames("retrieve_v")
        .iter()
        .map(|f| {
            f["specs"].as_array().unwrap().iter().map(|spec| {
                let (from, width) = span(&spec["span"]);
                (spec["doc"].as_str().unwrap().to_string(), from, width)
            }).collect()
        })
        .collect();
    assert_eq!(reads, [vec![(format!("{D}.1.1"), 5, 1), (format!("{D}.1.1"), 7, 2)], vec![(format!("{D}.2"), 5, 3)]], "D·5 at the daughter's V 5 and D·6–7 at its V 7 past the '-', one read; the retyped 'cat' at the head's V 5");
    assert!(dialer.ops().iter().all(|o| !o.starts_with("at:")), "every value read at the head: {:?}", dialer.ops());
}

/// Origins are BARE documents: an I-address minted under a member
/// resolves to the trunk, so the core's anchors are the trunk's
/// positions and a merger's `After` names one and is applied, never
/// ignored.
#[test]
fn origins_are_bare_documents_so_anchors_resolve() {
    assert_eq!(origin_of(&format!("{D}.0.1.12")), Some(a(D)));
    assert_eq!(
        origin_of(&format!("{D}.2.0.1.12")),
        Some(a(D)),
        "a version-qualified mint is the trunk's"
    );
    assert_eq!(origin_of(&format!("{D}.1.1.0.1.3")), Some(a(D)));
    assert_eq!(origin_of("1.0.1.0.1"), None);
    let mut w = World::race();
    w.text(D, 16, "fat ");
    w.member(&format!("{D}.1.2"), vec![run(D, 1, 4), run(D, 16, 4), run(D, 5, 7)], Some(11));
    let (_, board, _) = open(w);
    let both = Inputs { sides: vec![Side::Member(a(&format!("{D}.1.2")))], ..race_inputs() };
    let merged = compose(&board, Some(&token()), &both).expect("composed");
    assert_eq!(merged.composed.gaps.len(), 1);
    let gap = &merged.composed.gaps[0];
    assert_eq!(
        (gap.kind, gap.after.clone(), gap.before.clone()),
        (GapKind::Order, Some(a(&format!("{D}.0.1.4"))), Some(a(&format!("{D}.0.1.5"))))
    );
    let swapped = Inputs {
        options: Options {
            resolutions: vec![Resolution {
                gap: GapId(1),
                choice: Choice::Order(vec![SideIx(1), SideIx(0)]),
                by: ResolvedBy::Person,
            }],
            ..Options::default()
        },
        ..both.clone()
    };
    let merged = compose(&board, Some(&token()), &swapped).expect("composed");
    assert!(
        merged.composed.ignored.is_empty(),
        "the resolution names a gap the anchors resolve: {:?}",
        merged.composed.ignored
    );
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 4), run(D, 16, 4), run(D, 12, 4), run(D, 5, 7)],
        "the fat big cat sat"
    );
    assert_eq!(merged.record.gaps[0].resolved_by, Some(ResolvedBy::Person));
}

/// A draft side at a position is read through `/op-at` — its recorded
/// base first, then its extent and its image, each as of the position —
/// and so are the trunk's metadata and the head, the sides that can
/// change, so the record stands at one state; the base, a version below
/// the head, the same at every position, is read at the head, and nothing
/// is fenced. The record's side names that position: one `history_busy`
/// is retried and the read answers; past the bounded retries the
/// composition refuses `HistoryBusy`. The shot's values are read at the
/// head, the head's by its V-ordinals and the draft's by the I-addresses
/// its image served, never at the position.
#[test]
fn a_draft_at_a_position_retries_history_busy_then_refuses() {
    let (dialer, board, signer) = open(World::window_and_draft());
    let session = sign_in(&board, &signer);
    let at = dialer.world().position;
    dialer.world().busy = 1;
    dialer.clear();
    let inputs = Inputs {
        sides: vec![Side::Draft { at: a(S), position: Some(at) }],
        base: Some(a(&format!("{D}.1"))),
        ..race_inputs()
    };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7), run(S, 1, 3)]);
    assert_eq!(
        merged.families,
        vec![Family::Own, Family::Window, Family::Own, Family::DraftNative]
    );
    assert_eq!(
        dialer.positions("doc_metadata"),
        [at, at, at],
        "the named position: the trunk's metadata, one busy, one answered, then the draft's base: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.positions("retrieve_doc_v_span_set"), [at, at], "the head's and the draft's extent");
    assert_eq!(dialer.positions("image"), [at, at], "the head and the draft");
    let at_head: Vec<(String, Value)> = dialer
        .served
        .lock()
        .unwrap()
        .iter()
        .filter(|(line, _)| ["doc_metadata", "retrieve_doc_v_span_set", "image"].contains(&line.as_str()))
        .map(|(line, f)| (line.clone(), f.get("d").or(f.get("doc")).cloned().unwrap_or_default()))
        .collect();
    assert_eq!(
        at_head,
        [("retrieve_doc_v_span_set".to_string(), json!(format!("{D}.1"))), ("image".to_string(), json!(format!("{D}.1")))],
        "the base below the head, read at the head, and no fence: {:?}",
        dialer.ops()
    );
    assert_eq!(merged.as_of, at, "the one position the composition stands at");
    assert_eq!(
        merged.record.sides[1],
        SideAt::Draft { at: a(S), position: Some(at), arranged: SideState::At(at) },
        "the record's side names the position named, and the draft's state there — its last change the world's last commit"
    );
    dialer.clear();
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(dialer.ops().iter().all(|o| !o.starts_with("at:")), "the shot reads nothing at a position: {:?}", dialer.ops());
    assert_eq!(
        dialer.frames("retrieve_i"),
        [frames::retrieve_i(&[(&format!("{S}.0.1.1"), 3)])],
        "the draft's words by the addresses its image served"
    );
    dialer.world().busy = 10;
    assert_eq!(compose(&board, Some(&token()), &inputs), Err(Refusal::HistoryBusy));
}

/// THE RECORD NAMES THE POSITION A DRAFT SIDE WAS READ AT (skep #453): a
/// draft side named with no position is read at the head, fenced, and the
/// record's side carries the position its fences stood at — the head when
/// the composition began — the inputs as given. `verify` then reads the draft AND its
/// recorded base as of that position — its `doc_metadata`, its extent,
/// its image and the join's `compare` each through `/op-at` at it — so
/// once a publication of the draft itself has moved its base to the
/// member it minted, the merge's shot having kept it (skep #944), and
/// once the draft is edited past the shot, the record still verifies
/// Equal; the premise, the board's `doc_metadata` as of the position
/// answering the base that stood. A record naming no position reads the
/// draft as it stands, and is refused by name against the moved base.
#[test]
fn a_draft_sides_record_names_the_position_read_and_verifies_as_of_it() {
    let (dialer, board, signer) = open(World::window_and_draft());
    let session = sign_in(&board, &signer);
    let read_at = dialer.world().position;
    let inputs =
        Inputs { sides: vec![Side::Draft { at: a(S), position: None }], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert_eq!(
        merged.record.sides[1],
        SideAt::Draft { at: a(S), position: Some(read_at), arranged: SideState::At(read_at) },
        "the position the first read answered, and the draft's state there"
    );
    assert_eq!(merged.inputs, inputs, "the inputs as given");
    let ops = dialer.ops();
    assert!(ops.iter().all(|o| !o.starts_with("at:")), "every read at the head, the draft fenced: {ops:?}");
    let fenced = |doc: &str| dialer.frames("doc_metadata").iter().filter(|f| f["doc"] == doc).count();
    assert_eq!((fenced(S), fenced(&format!("{D}.2"))), (2, 2), "the draft and the head each read before their images and after: {ops:?}");
    // The shot renders the draft and keeps its recorded base; the record
    // read back names the position.
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    let Landed::Member { address, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(address.to_string(), format!("{D}.3"));
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(
        record.sides[1],
        SideAt::Draft { at: a(S), position: Some(read_at), arranged: SideState::At(read_at) }
    );
    let base_as_of = |at: Option<u64>| -> Option<String> {
        let frame = frames::doc_metadata(S);
        let v = match at {
            None => match board.op(Some(&token()), &frame).expect("the read") {
                Answer::Document(v) => v,
                Answer::Closed => panic!("closed"),
            },
            Some(at) => match board.op_at(Some(&token()), at, &frame).expect("the read") {
                AtAnswer::Document(v) => v,
                other => panic!("{other:?}"),
            },
        };
        v["base"].as_str().map(str::to_string)
    };
    assert_eq!(base_as_of(None), Some(format!("{D}.1")), "the merge's shot kept the draft's base");
    // A publication of the draft itself, off the trunk's head, moves it:
    // committed as the board commits one it admitted.
    let runs = [frames::shot_run(D, &format!("{D}.0.1.1"), 11), frames::shot_run(S, &format!("{S}.0.1.1"), 3)];
    let head = format!("{D}.3");
    let own = frames::publication(&frames::PublishFrame { doc: Some(D), base: Some((&head, 18)), draft: Some(S), runs: &runs, ..frames::PublishFrame::default() });
    let ack = dialer.world().apply(&own);
    assert_eq!(acked_addr(&ack), Some(format!("{D}.4").as_str()), "{ack}");
    assert_eq!(base_as_of(None), Some(format!("{D}.4")), "the base moved with the draft's own publication");
    assert_eq!(
        base_as_of(Some(read_at)),
        Some(format!("{D}.1")),
        "the premise: as of the record's position, the base that stood"
    );
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    for op in ["doc_metadata", "retrieve_doc_v_span_set", "image", "compare"] {
        let positions = dialer.positions(op);
        assert!(
            !positions.is_empty() && positions.iter().all(|p| *p == read_at),
            "`{op}` read as of the record's position: {positions:?}; {:?}",
            dialer.ops()
        );
    }
    assert_eq!(
        dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect::<Vec<_>>(),
        [json!(D), json!(S), json!(format!("{D}.3"))],
        "the trunk's and the draft's as of the position, the landed member's as it stands"
    );
    // The draft edited past the shot — its "!!!" deleted — and the record
    // still testifies to the state it composed from.
    let typed = dialer.world().position;
    match board.op(Some(session.token()), &frames::delete(S, 12, 3, typed, None)) {
        Ok(Answer::Document(v)) => assert_eq!(v["resp"], "ack", "{v}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, vec![run(D, 1, 11)]);
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    let mut headless = record.clone();
    let SideAt::Draft { position, .. } = &mut headless.sides[1] else {
        panic!("the draft side")
    };
    *position = None;
    assert_eq!(
        verify(&board, Some(&token()), &headless),
        Err(Refusal::DraftBaseDisagrees {
            side: Side::Draft { at: a(S), position: None },
            named: a(&format!("{D}.1")),
            served: a(&format!("{D}.2")),
        }),
        "a record naming no position reads the draft as it stands"
    );
}

/// A DRAFT SIDE's BASE IS READ OFF THE BOARD (skep #743): the draft's
/// `doc_metadata` is read for the base the board records for it — right
/// after the trunk's, as a fork's is for its source, its opening fence —
/// and the merge's base is derived from it, so the caller names none; the
/// reads then run in the record's order, each at the head — the base text
/// between the head's window and the draft's "!!!" read once through the
/// head by the line rule (skep #1173), which finds no line's edge there —
/// the prior records by the links of the kind to the draft, and nothing is
/// written. A base the caller names is checked, never trusted: one equal to
/// the derived base is taken; a different one refuses `DraftBaseDisagrees`,
/// naming both, before any `image`.
#[test]
fn a_draft_sides_base_is_read_off_the_board_and_a_named_one_must_agree() {
    let (dialer, board, _) = open(World::window_and_draft());
    let rows = dialer.world().rows.len();
    let side = Side::Draft { at: a(S), position: None };
    let inputs = Inputs { sides: vec![side.clone()], ..race_inputs() };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    assert_eq!(
        dialer.ops(),
        [
            "doc_metadata",
            "doc_metadata",
            "doc_metadata",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_doc_v_span_set",
            "image",
            "retrieve_v",
            "doc_metadata",
            "doc_metadata",
            "find_links_ftt"
        ]
    );
    assert_eq!(
        dialer.frames("retrieve_v")[0]["specs"][0]["doc"].as_str(),
        Some(format!("{D}.2").as_str()),
        "the line rule's read, through the head"
    );
    let metadata: Vec<String> = dialer
        .frames("doc_metadata")
        .iter()
        .map(|f| f["doc"].as_str().unwrap().to_string())
        .collect();
    let head = format!("{D}.2");
    assert_eq!(
        metadata,
        [D.to_string(), S.to_string(), head.clone(), S.to_string(), head],
        "the trunk's, the draft's opening fence, the head's, then their closing fences"
    );
    let imaged: Vec<String> =
        dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        imaged,
        [format!("{D}.2"), format!("{D}.1"), S.to_string()],
        "the head, the base the board records for the draft, the draft"
    );
    assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7), run(S, 1, 3)]);
    assert_eq!(
        merged.families,
        vec![Family::Own, Family::Window, Family::Own, Family::DraftNative]
    );
    assert_eq!(
        (merged.key.base.clone(), merged.record.base.clone()),
        (a(&format!("{D}.1")), a(&format!("{D}.1"))),
        "the base the board records for the draft, never named"
    );
    assert_eq!(
        merged.record.sides.iter().map(SideAt::role).collect::<Vec<_>>(),
        [Role::Head, Role::Draft]
    );
    assert_eq!(dialer.world().rows.len(), rows, "nothing written");
    // A named base equal to the derived one is taken; a different one is
    // refused by name, with the base the records derive, before any image.
    let named = |b: &str| Inputs { base: Some(a(b)), ..inputs.clone() };
    let agreed = compose(&board, Some(&token()), &named(&format!("{D}.1"))).expect("composed");
    assert_eq!((agreed.key.base.clone(), m_runs(&agreed)), (merged.key.base.clone(), m_runs(&merged)));
    dialer.clear();
    assert_eq!(
        compose(&board, Some(&token()), &named(&format!("{D}.2"))),
        Err(Refusal::DraftBaseDisagrees {
            side: side.clone(),
            named: a(&format!("{D}.2")),
            served: a(&format!("{D}.1")),
        })
    );
    assert!(
        !dialer.names().iter().any(|o| o == "image"),
        "no image before the refusal: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().rows.len(), rows, "nothing written");
}

/// THE MERGE's BASE IS DERIVED FROM THE DRAFT's RECORDED BASE, never the
/// recorded base itself: a draft staged from the daughter `D.1.1`, "!"
/// typed at its end, merged with the head `D.2` composes over `D.1` —
/// the nearest common ancestor of the head and the daughter — with no
/// base named, so the daughter's removal of " sat" is the draft's and
/// never an addition of the head's: "the big cat!". Naming the recorded
/// base `D.1.1` is refused `DraftBaseDisagrees` with `D.1` as the base
/// the board's record derives — the comparison is with the derived base
/// — while naming `D.1` is taken.
#[test]
fn a_draft_staged_from_a_daughter_composes_over_the_daughters_base() {
    let mut w = World::race();
    let t = "1.0.1.0.67";
    w.text(t, 1, "!");
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 7), run(t, 1, 1)]);
    w.staged(t, &format!("{D}.1.1"), 7);
    let (dialer, board, _) = open(w);
    let side = Side::Draft { at: a(t), position: None };
    let inputs = Inputs { sides: vec![side.clone()], ..race_inputs() };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    assert_eq!(
        merged.key.base,
        a(&format!("{D}.1")),
        "the nearest common ancestor of the head and the recorded base"
    );
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3), run(t, 1, 1)],
        "the big cat!"
    );
    assert_eq!(
        merged.families,
        vec![Family::Own, Family::Own, Family::Own, Family::DraftNative]
    );
    assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
    let imaged: Vec<String> =
        dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        imaged,
        [format!("{D}.2"), format!("{D}.1"), t.to_string()],
        "the head, then the derived base imaged, never the daughter"
    );
    let named = |b: &str| Inputs { base: Some(a(b)), ..inputs.clone() };
    assert_eq!(
        compose(&board, Some(&token()), &named(&format!("{D}.1.1"))),
        Err(Refusal::DraftBaseDisagrees {
            side: side.clone(),
            named: a(&format!("{D}.1.1")),
            served: a(&format!("{D}.1")),
        }),
        "the comparison is with the derived base, not the recorded one"
    );
    assert_eq!(
        compose(&board, Some(&token()), &named(&format!("{D}.1"))).expect("composed").key.base,
        a(&format!("{D}.1"))
    );
}

/// Composes `inputs` over `world()` twice — once untouched, the premise,
/// and once with `doc` arranged as `runs` by another hand right after its
/// image was read — and answers what the second composition answered.
fn edited_after_its_image(world: &dyn Fn() -> World, inputs: &Inputs, doc: &str, runs: Vec<Run>) -> Result<Merged, Refusal> {
    let (dialer, board, _) = open(world());
    compose(&board, Some(&token()), inputs).expect("the premise: it composes untouched");
    let image = dialer.served.lock().unwrap().iter().position(|(line, f)| line == "image" && f["d"] == doc).expect("its image");
    let mut w = world();
    // The frame after the image's, counted from 1.
    w.interleave = Some((image + 2, doc.to_string(), runs));
    let (dialer, board, _) = open(w);
    let answered = compose(&board, Some(&token()), inputs);
    assert!(dialer.world().interleave.is_none(), "{doc}: the edit landed mid-walk");
    answered
}

/// The draft landing's shape with `D.3`, the trunk's current head, one
/// deposit past `D.2`'s words: a trunk member that can still take one.
fn world_with_v3() -> World {
    let mut w = World::window_and_draft();
    w.text(D, 20, "??");
    w.member(&format!("{D}.3"), vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7), run(D, 20, 1)], Some(16));
    w.trunk_head.insert(D.to_string(), format!("{D}.3"));
    w
}

/// A SIDE THAT CHANGES WHILE THE COMPOSITION READS IT IS REFUSED (skep
/// #1144; the owner's ruling of 2026-11-22): every side that can change
/// is FENCED — its `doc_metadata` read before any image and again after
/// the images and the values, all at the head — and one another hand
/// edits right after its image was read refuses `SideMoved` naming it,
/// `before` and `after` its `arranged_at` at the two fences, `at` the
/// position the opening fences stood at, nothing written and nothing read
/// at a position: the draft side; a fork side; the head, a deposit
/// appended past its extent; and the trunk's current head named as a side
/// beside a draft, which can take a deposit too (F2; the mutant fencing
/// the draft alone composes over each of the others' edit, the one
/// fencing the head and the named head alone over the trunk member's).
#[test]
fn a_side_that_changes_while_the_composition_reads_it_is_refused_naming_it() {
    let refused = |world: &dyn Fn() -> World, inputs: &Inputs, doc: &str, runs: Vec<Run>| -> Refusal {
        edited_after_its_image(world, inputs, doc, runs).expect_err("refused")
    };
    let p = World::window_and_draft().position;
    assert_eq!(
        refused(&World::window_and_draft, &with_side(Side::Draft { at: a(S), position: None }), S, vec![run(D, 1, 11)]),
        Refusal::SideMoved { side: a(S), at: p, before: Some(p), after: Some(p + 1) },
        "the draft, its \"!!!\" deleted"
    );
    let with_fork = || {
        let mut w = World::race();
        w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
        w
    };
    let p = with_fork().position;
    assert_eq!(
        refused(&with_fork, &with_side(Side::Fork(a(F))), F, vec![run(D, 1, 4)]),
        Refusal::SideMoved { side: a(F), at: p, before: None, after: Some(p + 1) },
        "the fork, never arranged since its mint, then edited"
    );
    let with_deposit_text = || {
        let mut w = World::race();
        w.text(D, 16, "?");
        w
    };
    let p = World::race().position;
    let deposited = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 16, 1)];
    assert_eq!(
        refused(&with_deposit_text, &race_inputs(), &format!("{D}.2"), deposited),
        Refusal::SideMoved { side: a(&format!("{D}.2")), at: p, before: None, after: Some(p + 1) },
        "the head, a deposit past its extent"
    );
    let v3 = format!("{D}.3");
    let p = world_with_v3().position;
    let beside = Inputs { sides: vec![Side::Draft { at: a(S), position: None }, Side::Member(a(&v3))], ..race_inputs() };
    let deposited = vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7), run(D, 20, 2)];
    assert_eq!(
        refused(&world_with_v3, &beside, &v3, deposited),
        Refusal::SideMoved { side: a(&v3), at: p, before: None, after: Some(p + 1) },
        "the trunk's current head named as a side, a deposit past its extent"
    );
    // The words: the side changed while it was read, nothing merged, and
    // the way on.
    let said = Refusal::SideMoved { side: a(S), at: p, before: Some(p), after: Some(p + 1) }.to_string();
    assert!(
        said.contains(&format!("{S} changed while this merge was reading it (its text changed at position {})", p + 1))
            && said.contains("nothing was merged; compose the merge again"),
        "{said}"
    );
}

/// A DRAFT WHOSE RECORDED BASE MOVES WHILE THE COMPOSITION READS IT IS
/// REFUSED, ITS TEXT UNCHANGED (skep #1144): the draft's own publication
/// moves its recorded base and leaves its arrangement as it stood, so its
/// `arranged_at` stands too; the fence compares where the board records the
/// draft standing beside its state, and the composition refuses
/// `SideMoved` naming the draft, `before` and `after` the one position, its
/// words saying the recorded base moved and the text did not (the mutant
/// fencing by `arranged_at` alone composes over the base that stood at the
/// first read).
#[test]
fn a_drafts_recorded_base_moved_while_it_is_read_is_refused_its_text_unchanged() {
    let inputs = with_side(Side::Draft { at: a(S), position: None });
    let (dialer, board, _) = open(World::window_and_draft());
    compose(&board, Some(&token()), &inputs).expect("the premise: it composes unmoved");
    let image = dialer.served.lock().unwrap().iter().position(|(line, f)| line == "image" && f["d"] == S).expect("the draft's image");
    let mut w = World::window_and_draft();
    let p = w.position;
    w.rebase = Some((image + 2, S.to_string(), format!("{D}.2")));
    let (dialer, board, _) = open(w);
    let refused = compose(&board, Some(&token()), &inputs);
    {
        let w = dialer.world();
        assert!(w.rebase.is_none(), "the base moved mid-walk");
        assert_eq!(w.docs[S].history.keys().next_back(), Some(&p), "the premise: the text unmoved");
    }
    assert_eq!(refused, Err(Refusal::SideMoved { side: a(S), at: p, before: Some(p), after: Some(p) }));
    let said = refused.unwrap_err().to_string();
    assert!(
        said.contains(&format!("the base the board records for {S} moved while this merge was reading it, its text unchanged"))
            && said.contains("nothing was merged"),
        "{said}"
    );
}

/// A SIDE THAT IS A TRUNK MEMBER IS READ AS OF A DRAFT SIDE'S NAMED
/// POSITION (skep #1144, F2): the trunk's current head, named as a side
/// beside a draft side named at a position, can take a deposit, so it is
/// read as of that position as the head and the draft are — never at the
/// head, where a deposit landed since would stand beside the draft's past
/// state — while the base, a version below the head, the same at every
/// position, is read at the head.
#[test]
fn a_side_that_is_a_trunk_member_is_read_as_of_a_draft_sides_named_position() {
    let (dialer, board, _) = open(world_with_v3());
    let at = dialer.world().position;
    let v3 = format!("{D}.3");
    let inputs = Inputs {
        sides: vec![Side::Draft { at: a(S), position: Some(at) }, Side::Member(a(&v3))],
        ..race_inputs()
    };
    compose(&board, Some(&token()), &inputs).expect("composed");
    let imaged = |line: &str| -> Vec<(String, Option<u64>)> {
        dialer
            .served
            .lock()
            .unwrap()
            .iter()
            .filter(|(served, _)| served == line)
            .map(|(_, f)| match line {
                "at:image" => (f["frame"]["d"].as_str().unwrap().to_string(), f["at"].as_u64()),
                _ => (f["d"].as_str().unwrap().to_string(), None),
            })
            .collect()
    };
    assert_eq!(
        imaged("at:image"),
        [(format!("{D}.2"), Some(at)), (S.to_string(), Some(at)), (v3, Some(at))],
        "the head, the draft and the trunk member, each as of the position"
    );
    assert_eq!(imaged("image"), [(format!("{D}.1"), None)], "the base below the head, at the head");
}

/// A BOARD SERVING NO `arranged_at` CANNOT HOLD A SIDE TO ONE STATE (skep
/// #1144, F3): its `doc_metadata` answers carry no such member — an older
/// board — so a fence would pass over any edit, and the composition
/// refuses as the board's fault at the first fence, naming the side and
/// the member, with nothing imaged and nothing written — never as `null`,
/// a side never arranged (the mutant that reads the member absent as
/// `null` composes unguarded). A draft side named at a position, read as
/// of it and fenced not at all, composes on that board.
#[test]
fn a_board_serving_no_arranged_at_is_refused_at_the_first_fence_and_composes_nothing() {
    let mut w = World::window_and_draft();
    w.no_arranged_at = true;
    let (dialer, board, _) = open(w);
    let at = dialer.world().position;
    let err = compose(&board, Some(&token()), &with_side(Side::Draft { at: a(S), position: None }))
        .expect_err("refused");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("faced: {err:?}") };
    assert!(
        face.state.contains("arranged_at") && face.state.contains(S) && face.cause.contains("an older board"),
        "{face}"
    );
    assert!(face.act.contains("nothing was merged and nothing was written"), "{face}");
    assert_eq!(dialer.ops(), ["doc_metadata", "doc_metadata"], "the trunk's metadata, then the draft's opening fence, and nothing after");
    compose(&board, Some(&token()), &with_side(Side::Draft { at: a(S), position: Some(at) }))
        .expect("read as of the position named, no fence");
}

/// THE DEDUP'S VALUES ARE READ TOGETHER: a head and a daughter each adding
/// a one-byte word at each of g spots raise g `order` gaps, whose groups
/// the dedup compares, and the composition reads their values in two
/// `retrieve_v` reads — one through each side — at g = 2 and at g = 8, never
/// one a run. The composition is the one the core makes reading each run as
/// it asks it: the matching words kept once, the gap settled by the rule,
/// the others asked (the mutant reading one run at a time sends 2g reads).
#[test]
fn the_dedups_values_are_read_together_through_each_side() {
    for g in [2u64, 8] {
        let mut w = World::new();
        let base_text: String = (0..=g).map(|k| char::from(b'a' + k as u8)).collect();
        w.text(D, 1, &base_text);
        let (mut head, mut daughter) = (Vec::new(), Vec::new());
        let mut bytes: BTreeMap<u64, u8> = BTreeMap::new();
        for (k, b) in base_text.bytes().enumerate() {
            bytes.insert(1 + k as u64, b);
        }
        for k in 1..=g {
            let (ours, theirs) = (100 + k, 200 + k);
            let word = if k % 2 == 0 { "X" } else { "Y" };
            let other = if k % 2 == 0 { "X" } else { "Z" };
            w.text(D, ours, word);
            w.text(D, theirs, other);
            bytes.insert(ours, word.as_bytes()[0]);
            bytes.insert(theirs, other.as_bytes()[0]);
            head.extend([run(D, k, 1), run(D, ours, 1)]);
            daughter.extend([run(D, k, 1), run(D, theirs, 1)]);
        }
        head.push(run(D, g + 1, 1));
        daughter.push(run(D, g + 1, 1));
        w.doc(D, true, ACCOUNT, head.clone());
        w.member(&format!("{D}.1"), vec![run(D, 1, g + 1)], None);
        w.member(&format!("{D}.2"), head.clone(), Some(g + 1));
        w.member(&format!("{D}.1.1"), daughter.clone(), Some(g + 1));
        w.trunk_head.insert(D.to_string(), format!("{D}.2"));
        let (dialer, board, _) = open(w);
        let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        assert_eq!(
            dialer.frames("retrieve_v").len(),
            2,
            "g = {g}: one read through each side: {:?}",
            dialer.ops()
        );
        let values = |_: SideIx, r: &Run| Some((r.i_start..r.reach()).map(|p| vec![bytes[&p]]).collect::<Vec<Item>>());
        let sides = [(SideIx(0), head), (SideIx(1), daughter)];
        let one_at_a_time = compose_runs(&[run(D, 1, g + 1)], &a(D), &sides, None, &Options::default(), &values);
        assert_eq!(merged.composed, one_at_a_time, "g = {g}: the composition read a run at a time");
        let kept_once: Vec<GapId> = (1..=g as u32).filter(|k| k % 2 == 0).map(GapId).collect();
        assert_eq!(merged.composed.values.applied, kept_once, "g = {g}: the matching words kept once");
        assert_eq!(
            merged.composed.gaps.iter().map(|gap| gap.settled).collect::<Vec<_>>(),
            (1..=g).map(|k| k % 2 == 0).collect::<Vec<_>>(),
            "g = {g}"
        );
    }
}

/// The line cells' world (skep #1173): the base `D.1` "one\ntwo reads the
/// model. The\nthree\n" (`D·1–35`, line 2's break `D·29`), the head `D.2`
/// adding "h1\nh2 The\n" (`D·36–45`) right after that break, and the
/// daughter `D.1.1` rewriting inside line 2, "Every\ns1 " (`D·46–54`)
/// after `D·25`, before its kept "The\n".
fn lined_world() -> World {
    let mut w = World::new();
    w.text(D, 1, "one\ntwo reads the model. The\nthree\n");
    w.text(D, 36, "h1\nh2 The\n");
    w.text(D, 46, "Every\ns1 ");
    let head = vec![run(D, 1, 29), run(D, 36, 10), run(D, 30, 6)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), vec![run(D, 1, 35)], None);
    w.member(&format!("{D}.2"), head, Some(35));
    w.member(&format!("{D}.1.1"), vec![run(D, 1, 25), run(D, 46, 9), run(D, 26, 10)], Some(35));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    w
}

/// THE LINE RULE READS THE BASE TEXT TOGETHER (skep #1173): a rewrite
/// inside a line beside the head's lines right after its break is two
/// `line` gaps, unsettled, M as composed with no rule; the base text the
/// rule reads — `D·25` and `D·26–29` — goes out in ONE `retrieve_v`
/// through the head, with the dedup on and with it off, and the
/// composition is the one the core makes reading each run as it asks it
/// (the mutant that batches the reads only with the dedup on sends two
/// with it off). A record of the merge landed at the defaults verifies
/// Equal.
#[test]
fn a_line_edge_reads_the_base_text_in_one_read_through_the_head() {
    let (dialer, board, signer) = open(lined_world());
    let session = sign_in(&board, &signer);
    let head = vec![run(D, 1, 29), run(D, 36, 10), run(D, 30, 6)];
    let daughter = vec![run(D, 1, 25), run(D, 46, 9), run(D, 26, 10)];
    let bytes: Vec<u8> = b"one\ntwo reads the model. The\nthree\nh1\nh2 The\nEvery\ns1 ".to_vec();
    let values = |_: SideIx, r: &Run| {
        Some((r.i_start..r.reach()).map(|p| vec![bytes[p as usize - 1]]).collect::<Vec<Item>>())
    };
    for dedup in [true, false] {
        dialer.clear();
        let options = Options { dedup, ..Options::default() };
        let inputs = Inputs { options: options.clone(), ..race_inputs() };
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        let reads = dialer.frames("retrieve_v");
        assert_eq!(reads.len(), 1, "dedup {dedup}: one read: {:?}", dialer.ops());
        assert_eq!(
            reads[0]["specs"][0]["doc"].as_str(),
            Some(format!("{D}.2").as_str()),
            "dedup {dedup}: through the head"
        );
        let kinds: Vec<(GapKind, bool)> =
            merged.composed.gaps.iter().map(|g| (g.kind, g.settled)).collect();
        assert_eq!(kinds, [(GapKind::Line, false), (GapKind::Line, false)], "dedup {dedup}");
        assert_eq!(
            m_runs(&merged),
            vec![run(D, 1, 25), run(D, 46, 9), run(D, 26, 4), run(D, 36, 10), run(D, 30, 6)],
            "dedup {dedup}: M at the defaults"
        );
        let sides = [(SideIx(0), head.clone()), (SideIx(1), daughter.clone())];
        let one_at_a_time = compose_runs(&[run(D, 1, 35)], &a(D), &sides, None, &options, &values);
        assert_eq!(
            merged.composed, one_at_a_time,
            "dedup {dedup}: the composition read a run at a time"
        );
    }
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, shot(&session, &signer)).expect("landed at the defaults");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(
        record.gaps.iter().map(|g| g.kind).collect::<Vec<_>>(),
        [GapKind::Line, GapKind::Line]
    );
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
}

/// THE LINE RULE READS WHAT DECIDES IT, WHATEVER THE DOCUMENT'S LENGTH
/// (skep #1173): over the base `D.1`, "abcdefgh\n" `L` times (`N` = 9L), the
/// head `D.2` adds "X" after `D·2` and the daughter `D.1.1` "Y" after
/// `D·(N−3)`, two additions a document apart, inside two lines. The merge
/// asks nothing, M is the two additions in their places, the composition
/// is the one the core makes reading each run as it asks it, and the
/// positions read through the head sum to at most `LINE_READ` + 2, at
/// `L` = 1,000 and at `L` = 10,000 (the mutant reading the whole text
/// between them reads `N` − 4).
#[test]
fn the_line_rule_reads_what_decides_it_whatever_the_documents_length() {
    for l in [1_000u64, 10_000] {
        let n = 9 * l;
        let base_text = "abcdefgh\n".repeat(l as usize);
        let mut w = World::new();
        w.text(D, 1, &base_text);
        w.text(D, n + 1, "X");
        w.text(D, n + 2, "Y");
        let head = vec![run(D, 1, 2), run(D, n + 1, 1), run(D, 3, n - 2)];
        let daughter = vec![run(D, 1, n - 3), run(D, n + 2, 1), run(D, n - 2, 3)];
        w.doc(D, true, ACCOUNT, head.clone());
        w.member(&format!("{D}.1"), vec![run(D, 1, n)], None);
        w.member(&format!("{D}.2"), head.clone(), Some(n));
        w.member(&format!("{D}.1.1"), daughter.clone(), Some(n));
        w.trunk_head.insert(D.to_string(), format!("{D}.2"));
        let (dialer, board, _) = open(w);
        let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        assert!(merged.composed.gaps.is_empty(), "L = {l}: {:?}", merged.composed.gaps);
        assert_eq!(
            m_runs(&merged),
            vec![
                run(D, 1, 2),
                run(D, n + 1, 1),
                run(D, 3, n - 5),
                run(D, n + 2, 1),
                run(D, n - 2, 3)
            ],
            "L = {l}: M"
        );
        let mut bytes = base_text.into_bytes();
        bytes.extend(b"XY");
        let values = |_: SideIx, r: &Run| {
            Some((r.i_start..r.reach()).map(|p| vec![bytes[p as usize - 1]]).collect::<Vec<Item>>())
        };
        let sides = [(SideIx(0), head), (SideIx(1), daughter)];
        let one_at_a_time =
            compose_runs(&[run(D, 1, n)], &a(D), &sides, None, &Options::default(), &values);
        assert_eq!(merged.composed, one_at_a_time, "L = {l}: the composition read a run at a time");
        let through_head: u64 = dialer
            .frames("retrieve_v")
            .iter()
            .flat_map(|f| f["specs"].as_array().cloned().unwrap_or_default())
            .filter(|s| s["doc"].as_str() == Some(format!("{D}.2").as_str()))
            .map(|s| span(&s["span"]).1)
            .sum();
        assert!(
            through_head <= crate::merge::compose::LINE_READ + 2,
            "L = {l}: {through_head} positions read through the head: {:?}",
            dialer.ops()
        );
    }
}

/// A WINDOW WITHHELD IN THE TEXT THAT DECIDES THE LINE RULE IS REFUSED BY
/// NAME, WHATEVER THE SWITCHES (skep #1174): the base `D.1` "ab" `W`'s
/// "c\n" "de\n" — a window onto another account's draft ending line 1 —
/// the head adding "X" after `D·1`, inside line 1, the daughter "Y" right
/// after line 1's break, so the rule reads `W` to decide the pair. With
/// `W` readable, two `line` gaps, the first's `after` `D·1` and the
/// second's `before` `D·3`, and a record of the merge, dedup off, verifies
/// Equal against a member holding M; with `W` withheld, the composition
/// with the dedup off, on and with the retype refuses `LineTextWithheld`
/// naming `W` and that place — never `Unreadable(W)`, a side's refusal —
/// the masked value read its last (SP-14), and the record answers
/// Unreadable naming `W` (the mutants whose line rule reads no value with
/// the dedup off, that refuse as `Unreadable`, that name the text's own
/// ends).
#[test]
fn a_withheld_window_in_the_text_deciding_the_line_rule_is_refused_naming_the_pair() {
    const W: &str = "1.0.2.0.70";
    let mut w = World::new();
    w.text(D, 1, "abde\n");
    w.text(D, 10, "X");
    w.text(D, 20, "Y");
    w.text(W, 1, "c\n");
    w.doc(W, false, "1.0.2", vec![run(W, 1, 2)]);
    let base = vec![run(D, 1, 2), run(W, 1, 2), run(D, 3, 3)];
    let head = vec![run(D, 1, 1), run(D, 10, 1), run(D, 2, 1), run(W, 1, 2), run(D, 3, 3)];
    let m =
        vec![run(D, 1, 1), run(D, 10, 1), run(D, 2, 1), run(W, 1, 2), run(D, 20, 1), run(D, 3, 3)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), base, None);
    w.member(&format!("{D}.2"), head, Some(5));
    w.member(
        &format!("{D}.1.1"),
        vec![run(D, 1, 2), run(W, 1, 2), run(D, 20, 1), run(D, 3, 3)],
        Some(5),
    );
    w.member(&format!("{D}.3"), m.clone(), Some(6));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let (dialer, board, _) = open(w);
    let off = Inputs { options: Options { dedup: false, ..Options::default() }, ..race_inputs() };
    let on = race_inputs();
    let retype = Inputs { options: Options { retype: true, ..Options::default() }, ..race_inputs() };
    let merged = compose(&board, Some(&token()), &off).expect("composed, W readable");
    assert_eq!(m_runs(&merged), m, "the premise: M");
    let kinds: Vec<(GapKind, bool)> =
        merged.composed.gaps.iter().map(|g| (g.kind, g.settled)).collect();
    assert_eq!(
        kinds,
        [(GapKind::Line, false), (GapKind::Line, false)],
        "the premise: the rule fires"
    );
    let (after, before) = (merged.composed.gaps[0].after.clone(), merged.composed.gaps[1].before.clone());
    assert_eq!(
        (&after, &before),
        (&Some(a(&format!("{D}.0.1.1"))), &Some(a(&format!("{D}.0.1.3")))),
        "the premise: the pair's place"
    );
    let mut record = merged.record.clone();
    record.landed = Some(RecordLanding::Member { member: a(&format!("{D}.3")), position: 0 });
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
    dialer.world().withheld.insert(W.to_string());
    let refused = Refusal::LineTextWithheld { doc: a(W), after, before };
    for inputs in [&off, &on, &retype] {
        dialer.clear();
        assert_eq!(compose(&board, Some(&token()), inputs), Err(refused.clone()), "{:?}", inputs.options);
        assert_eq!(
            dialer.ops().last().map(String::as_str),
            Some("retrieve_v"),
            "the masked value read is the last: {:?}",
            dialer.ops()
        );
    }
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(W))));
}

/// A WINDOW PAST THE TEXT THAT DECIDES THE LINE RULE IS NEVER READ (skep
/// #1174): the base `D.1` `LINE_READ` + 10 "a"s of `D`, `W`'s "cc", then
/// "de\n"; the head adds "X" after `D·1`, the daughter "Y" after the "d".
/// The text between them ends in "d" and the first stands inside a line,
/// so the rule's first reads — the position before the first, the text's
/// first `LINE_READ` positions and its last byte — decide it, `W` past
/// them, and the two ask nothing. With `W` withheld, the composition with
/// the dedup off, on and with the retype answers what it answers with `W`
/// readable — M and no gap — and the record of it verifies Equal (the
/// mutant that reads each later run's first position refuses).
#[test]
fn a_withheld_window_past_the_text_deciding_the_line_rule_is_never_read() {
    const W: &str = "1.0.2.0.70";
    let m = crate::merge::compose::LINE_READ + 10;
    let mut w = World::new();
    w.text(D, 1, &"a".repeat(m as usize));
    w.text(D, m + 1, "de\n");
    w.text(D, m + 10, "X");
    w.text(D, m + 20, "Y");
    w.text(W, 1, "cc");
    w.doc(W, false, "1.0.2", vec![run(W, 1, 2)]);
    let base = vec![run(D, 1, m), run(W, 1, 2), run(D, m + 1, 3)];
    let head =
        vec![run(D, 1, 1), run(D, m + 10, 1), run(D, 2, m - 1), run(W, 1, 2), run(D, m + 1, 3)];
    let daughter =
        vec![run(D, 1, m), run(W, 1, 2), run(D, m + 1, 1), run(D, m + 20, 1), run(D, m + 2, 2)];
    let merged_list = vec![
        run(D, 1, 1),
        run(D, m + 10, 1),
        run(D, 2, m - 1),
        run(W, 1, 2),
        run(D, m + 1, 1),
        run(D, m + 20, 1),
        run(D, m + 2, 2),
    ];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), base, None);
    w.member(&format!("{D}.2"), head, Some(m + 5));
    w.member(&format!("{D}.1.1"), daughter, Some(m + 5));
    w.member(&format!("{D}.3"), merged_list.clone(), Some(m + 6));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let (dialer, board, _) = open(w);
    let off = Inputs { options: Options { dedup: false, ..Options::default() }, ..race_inputs() };
    let on = race_inputs();
    let retype = Inputs { options: Options { retype: true, ..Options::default() }, ..race_inputs() };
    let switches = [&off, &on, &retype];
    let readable: Vec<Merged> = switches
        .iter()
        .map(|inputs| compose(&board, Some(&token()), inputs).expect("composed, W readable"))
        .collect();
    assert_eq!(m_runs(&readable[0]), merged_list, "the premise: M");
    assert!(
        readable[0].composed.gaps.is_empty(),
        "the premise: nothing asked: {:?}",
        readable[0].composed.gaps
    );
    let mut record = readable[0].record.clone();
    record.landed = Some(RecordLanding::Member { member: a(&format!("{D}.3")), position: 0 });
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
    dialer.world().withheld.insert(W.to_string());
    for (inputs, readable) in switches.iter().zip(&readable) {
        let merged = compose(&board, Some(&token()), inputs)
            .unwrap_or_else(|r| panic!("{:?}: composed past the text, W withheld: {r}", inputs.options));
        assert_eq!(merged.composed, readable.composed, "{:?}: as with W readable", inputs.options);
    }
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
}

/// A WINDOW WITHHELD IN A REMOVAL'S PAIR IS REFUSED NAMING THE REMOVAL'S
/// PLACE (skep #1174, #1176): the base `D.1` "ab" `W`'s "c\n" "de\n", the
/// head removing "b" (`D·2`) inside line 1 and the daughter adding "Y"
/// right after line 1's break, so the rule reads `W` to decide the pair.
/// With `W` readable, one `line` gap, naming the removal after `D·1`; with
/// `W` withheld, the composition with the dedup off, on and with the retype
/// refuses `LineTextWithheld` naming `W`, the removal's `after` and the
/// addition's `before`, `D·3` (the mutant that names the pair by the
/// addition's anchors alone names `W·2`).
#[test]
fn a_withheld_window_in_a_removals_pair_is_refused_naming_the_removals_place() {
    const W: &str = "1.0.2.0.70";
    let mut w = World::new();
    w.text(D, 1, "abde\n");
    w.text(D, 20, "Y");
    w.text(W, 1, "c\n");
    w.doc(W, false, "1.0.2", vec![run(W, 1, 2)]);
    let base = vec![run(D, 1, 2), run(W, 1, 2), run(D, 3, 3)];
    let head = vec![run(D, 1, 1), run(W, 1, 2), run(D, 3, 3)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), base, None);
    w.member(&format!("{D}.2"), head, Some(5));
    w.member(&format!("{D}.1.1"), vec![run(D, 1, 2), run(W, 1, 2), run(D, 20, 1), run(D, 3, 3)], Some(5));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let (dialer, board, _) = open(w);
    let off = Inputs { options: Options { dedup: false, ..Options::default() }, ..race_inputs() };
    let merged = compose(&board, Some(&token()), &off).expect("composed, W readable");
    let gaps: Vec<(GapKind, bool, Vec<Removed>)> =
        merged.composed.gaps.iter().map(|g| (g.kind, g.settled, g.removed.clone())).collect();
    let removed = Removed { side: SideIx(0), after: Some(a(&format!("{D}.0.1.1"))), before: Some(a(&format!("{W}.0.1.1"))) };
    assert_eq!(gaps, [(GapKind::Line, false, vec![removed.clone()])], "the premise: the removal asks");
    let before = merged.composed.gaps[0].before.clone();
    assert_eq!(before, Some(a(&format!("{D}.0.1.3"))), "the premise: the addition's place");
    dialer.world().withheld.insert(W.to_string());
    let refused = Refusal::LineTextWithheld { doc: a(W), after: removed.after, before };
    let on = race_inputs();
    let retype = Inputs { options: Options { retype: true, ..Options::default() }, ..race_inputs() };
    for inputs in [&off, &on, &retype] {
        assert_eq!(compose(&board, Some(&token()), inputs), Err(refused.clone()), "{:?}", inputs.options);
    }
}

/// A REMOVAL AT A LINE'S EDGE IS ASKED, RECORDED AND VERIFIED (skep #1176):
/// over the lined base `D.1`, the head `D.2` removes "eads " (`D·10–14`)
/// inside line 2 and the daughter `D.1.1` adds "h1\nh2 The\n" (`D·36–45`)
/// right after that line's break. The composition asks: one `line` gap,
/// unsettled, holding the daughter's words and naming the head's removal
/// between `D·9` and `D·15`. Settled `omit`, the merge leaves the words out
/// and the removal stands, the resolution applied; its record reads back
/// from its JSON with the removal named and verifies Equal against a
/// member holding M (the mutant that weighs no removal leaves the
/// resolution in `ignored`, and the record verifies `Differs`).
#[test]
fn a_removal_at_a_lines_edge_is_asked_recorded_and_verified() {
    let mut w = World::new();
    w.text(D, 1, "one\ntwo reads the model. The\nthree\n");
    w.text(D, 36, "h1\nh2 The\n");
    let head = vec![run(D, 1, 9), run(D, 15, 21)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), vec![run(D, 1, 35)], None);
    w.member(&format!("{D}.2"), head.clone(), Some(35));
    w.member(&format!("{D}.1.1"), vec![run(D, 1, 29), run(D, 36, 10), run(D, 30, 6)], Some(35));
    w.member(&format!("{D}.3"), head.clone(), Some(30));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let (_, board, _) = open(w);
    let removed = vec![Removed {
        side: SideIx(0),
        after: Some(a(&format!("{D}.0.1.9"))),
        before: Some(a(&format!("{D}.0.1.15"))),
    }];
    let asked = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    assert_eq!(
        asked.composed.gaps.iter().map(|g| (g.kind, g.settled, g.removed.clone())).collect::<Vec<_>>(),
        [(GapKind::Line, false, removed.clone())],
        "the premise: the removal asks"
    );
    let omit = Resolution { gap: GapId(1), choice: Choice::Omit, by: ResolvedBy::Person };
    let inputs = Inputs {
        options: Options { resolutions: vec![omit], ..Options::default() },
        ..race_inputs()
    };
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    assert!(merged.composed.ignored.is_empty(), "the gap takes it: {:?}", merged.composed.ignored);
    assert_eq!(m_runs(&merged), head, "the words left out, the removal standing");
    let mut record = Record::from_value(&merged.record.to_value()).expect("the record reads back");
    assert_eq!(record.gaps, merged.record.gaps, "read back, the removal named");
    assert_eq!(record.gaps[0].removed, removed);
    record.landed = Some(RecordLanding::Member { member: a(&format!("{D}.3")), position: 0 });
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
}
