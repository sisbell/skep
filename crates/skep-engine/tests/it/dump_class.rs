//! The world dump at a READER'S CLASS (PUB round 2, lane 3.4 §3/§4), through
//! the assembled engine: the v5 format's two publication-round sections, and
//! the per-class post-filter over the harness-only walk — the same tree,
//! filtered by the threaded predicate before render. The daemon's suite
//! holds the wire oracle (H4: `/dump` equals this post-filter byte for byte);
//! what is tested here is the engine's own: the filter under the total
//! predicate IS the walk, the guest's slice is empty, an owner's lists its
//! drafts, a grantee's follows the grant, a stranger's is the guest's, each
//! class is deterministic (PUB-8.26), and a historical world dumps at the
//! HEAD's class (PUB-6.48).

use crate::common;

use common::*;
use skep_address::Address;
use skep_arrangement::Caller;
use skep_content::Val;
use skep_engine::{Engine, World};
use skep_kernel::Seq;
use skep_links::SlotArg;
use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};
use tempfile::tempdir;

/// The GRANTS class type address (COMMONS DECISION 5 — 1.1.0.1.0.1.0.3.90).
fn t_grant() -> Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 90])
}

const A: PrincipalId = PrincipalId(1);
const B: PrincipalId = PrincipalId(2);
/// A principal with no account: a stranger to every subtree, ungranted.
const STRANGER: PrincipalId = PrincipalId(3);

/// The content byte the draft holds — three values whose rendering, `[201,
/// 202, 203]`, appears in no other line of the dump.
const SECRET: [u8; 3] = [201, 202, 203];

struct Board {
    acct_a: Address,
    home_a: Address,
    draft_a: Address,
    /// The one link in the draft — its dotted address is what the hints name.
    link_a: Address,
    acct_b: Address,
}

/// Two accounts under the genesis node: A (principal 1) with a published home
/// and a private DRAFT holding one secret content value and one link; B
/// (principal 2), a stranger to A's subtree until granted.
fn board(engine: &Engine) -> Board {
    let ns = engine.namespace();
    let prefix = |engine: &Engine| {
        engine.kernel().snapshot().world().m3().next_account_prefix(&node1()).expect("a prefix")
    };
    let (acct_a, _) = ns.delegate(BOOTSTRAP_PRINCIPAL, prefix(engine).tumbler().clone(), A).expect("A");
    let (home_a, _) = ns.create_new_document(A, &acct_a, None).expect("A's published home");
    let (draft_a, _) = ns.create_new_document(A, &acct_a, None).expect("A's private draft");
    let (acct_b, _) = ns.delegate(BOOTSTRAP_PRINCIPAL, prefix(engine).tumbler().clone(), B).expect("B");
    let owner = Caller::Principal(A);
    engine
        .vstream()
        .insert(
            owner,
            &draft_a,
            vp(1, 1),
            vec![Val::new(SECRET.to_vec()), Val::new(vec![b'x'])],
            false,
        )
        .expect("the owner writes its draft");
    let (link_a, _) = engine
        .linkstore(&World::visible_to(owner))
        .makelink(
            owner,
            &draft_a,
            SlotArg::Resolve(vec![vspec(&draft_a, 1, 1)]),
            SlotArg::Resolve(vec![vspec(&draft_a, 2, 1)]),
            SlotArg::Resolve(vec![vspec(&draft_a, 1, 2)]),
        )
        .unwrap_or_else(|_| panic!("the owner links within its draft"));
    Board { acct_a, home_a, draft_a, link_a, acct_b }
}

/// A grant of `content_prefix` to `grantee`, issued by A from its doc 1.
fn grant(engine: &Engine, b: &Board, content_prefix: &Address, grantee: &Address) -> Address {
    let issuer = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(issuer))
        .makelink(
            issuer,
            &b.home_a,
            SlotArg::Addrs(vec![content_prefix.clone()]),
            SlotArg::Addrs(vec![grantee.clone()]),
            SlotArg::Addrs(vec![t_grant()]),
        )
        .map(|(addr, _)| addr)
        .unwrap_or_else(|_| panic!("the grant deposits into A's doc 1"))
}

fn quoted(a: &Address) -> String {
    format!("{:?}", a.to_string())
}

fn secret_line() -> String {
    format!("[{}, {}, {}]", SECRET[0], SECRET[1], SECRET[2])
}

/// The v5 format: the banner, the PUBLICATION section listing the draft, and
/// the GRANT section holding the fold's operative record with its four
/// fields — and the faithfulness check, which now compares the grant fold's
/// seed against its fold through that section, still green.
#[test]
fn the_v5_format_names_the_publication_slice_and_the_grant_fold() {
    let engine = mem_engine();
    let b = board(&engine);
    let g = grant(&engine, &b, &b.draft_a, &b.acct_b);
    let text = engine.world_dump().into_string();

    assert!(text.starts_with("skep-world-dump v5\n"), "unexpected banner: {text:.32}");
    let publication = format!("\"publication\": [{}]", quoted(&b.draft_a));
    assert!(text.contains(&publication), "expected {publication} in:\n{text}");
    let grants = format!(
        "\"grants\": {{{}: {{\"content_prefix\": {}, \"grantee\": {}, \"home\": {}, \"issuer\": {}}}}}",
        quoted(&g),
        quoted(&b.draft_a),
        quoted(&b.acct_b),
        quoted(&b.home_a),
        quoted(&b.acct_a),
    );
    assert!(text.contains(&grants), "expected {grants} in:\n{text}");
    engine.check_hints().expect("the grant fold's seed equals its fold, through the section");
}

/// The filter under the TOTAL predicate is the harness-only walk, byte for
/// byte — the two are one tree rendered twice.
#[test]
fn the_filter_under_the_total_predicate_is_the_harness_walk() {
    let engine = mem_engine();
    let b = board(&engine);
    grant(&engine, &b, &b.draft_a, &b.acct_b);
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    assert_eq!(engine.dump_of_visible(world, &|_: &Address| true), engine.dump_of(world));
}

/// The GUEST (no principal): the publication slice EMPTY, the exception-set
/// hint empty, no content line of the draft, no link of the draft in any
/// hint family — while the published home's grant and the identity section
/// stay. A STRANGER principal — no account, no grant — reads exactly what the
/// guest reads.
#[test]
fn a_guest_s_dump_holds_no_draft_content_and_an_empty_slice() {
    let engine = mem_engine();
    let b = board(&engine);
    let g = grant(&engine, &b, &b.draft_a, &b.acct_b);

    let guest = engine.world_dump_visible_to(None).into_string();
    assert!(guest.starts_with("skep-world-dump v5\n"), "one banner for every class");
    assert!(guest.contains("\"publication\": []"), "the guest's slice is EMPTY:\n{guest}");
    assert!(guest.contains("\"publication.drafts\": {}"), "…and so is the hint:\n{guest}");
    assert!(!guest.contains(&secret_line()), "a draft's content line leaves:\n{guest}");
    assert!(!guest.contains(&quoted(&b.link_a)), "a draft's link leaves every hint:\n{guest}");
    assert!(guest.contains(&quoted(&g)), "the published home's grant link stays:\n{guest}");
    // The grant section is kept whole, so the draft the guest cannot open is
    // still named there, as that grant's `content_prefix` — the one dotted
    // rendering of it a guest's text carries. (The identity section names it
    // too, but in the authoritative maps' tumbler form, not this one.)
    assert!(
        guest.contains(&quoted(&b.draft_a)),
        "the whole-kept grant section still names the draft:\n{guest}"
    );

    let stranger = engine.world_dump_visible_to(Some(STRANGER));
    assert_eq!(stranger.as_str(), guest, "a stranger's class is the guest's");
}

/// The OWNER lists its drafts and reads their content and links; the
/// GRANTEE follows the grant — before it, B's dump is the guest's; after it,
/// B's holds the draft's slice entry, content and link — and the owner's and
/// the grantee's dumps agree once both read the same set.
#[test]
fn an_owner_lists_its_drafts_and_a_grantee_follows_the_grant() {
    let engine = mem_engine();
    let b = board(&engine);

    let before = engine.world_dump_visible_to(Some(B));
    assert_eq!(before, engine.world_dump_visible_to(None), "ungranted, B reads as the guest");

    let owner = engine.world_dump_visible_to(Some(A)).into_string();
    let slice = format!("\"publication\": [{}]", quoted(&b.draft_a));
    assert!(owner.contains(&slice), "the owner's slice lists its draft:\n{owner}");
    assert!(owner.contains(&secret_line()), "…with its content line:\n{owner}");
    assert!(owner.contains(&quoted(&b.link_a)), "…and its link in the hints:\n{owner}");

    grant(&engine, &b, &b.draft_a, &b.acct_b);
    let grantee = engine.world_dump_visible_to(Some(B)).into_string();
    assert!(grantee.contains(&slice), "the grantee's slice holds the granted draft:\n{grantee}");
    assert!(grantee.contains(&secret_line()), "…and its content line:\n{grantee}");
    assert!(grantee.contains(&quoted(&b.link_a)), "…and its link:\n{grantee}");
    assert_eq!(
        grantee,
        engine.world_dump_visible_to(Some(A)).into_string(),
        "owner and grantee read one set, so they dump one text"
    );
}

/// PUB-8.26, per class: two dumps of one world at one class are byte-equal,
/// and two engines driven by one script dump byte-equal at every class — the
/// text is a function of the world and the class alone.
#[test]
fn two_dumps_of_equal_worlds_are_byte_equal_per_class() {
    let build = || {
        let engine = mem_engine();
        let b = board(&engine);
        grant(&engine, &b, &b.draft_a, &b.acct_b);
        engine
    };
    let (e1, e2) = (build(), build());
    for class in [None, Some(A), Some(B), Some(STRANGER)] {
        let d1 = e1.world_dump_visible_to(class);
        assert_eq!(d1, e1.world_dump_visible_to(class), "{class:?}: one world, one text");
        assert_eq!(d1, e2.world_dump_visible_to(class), "{class:?}: equal worlds, equal texts");
    }
}

/// The historical shape (PUB-6.48, `/dump?at=N`'s two worlds): the N-world's
/// state, filtered at the HEAD's class. A grant committed AFTER N makes the
/// draft readable to B in the N-world's dump — its content line appears —
/// while the publication slice is the AS-OF-N set: a second draft minted
/// after N is in the head's slice and not in the N-world's.
#[test]
fn a_historical_world_dumps_at_the_head_s_class() {
    let dir = tempdir().expect("tempdir");
    let engine = Engine::open(fsync_cfg(dir.path())).expect("open");
    let b = board(&engine);
    let n: Seq = engine.kernel().current_seq();

    // After N: the grant, and a second draft.
    grant(&engine, &b, &b.draft_a, &b.acct_b);
    let (draft_2, _) =
        engine.namespace().create_new_document(A, &b.acct_a, None).expect("A's second draft");

    let head = engine.kernel().snapshot();
    let world_n = engine.world_at(n).expect("the N-world reconstructs");

    // The N-world at B's HEAD class: the draft's content is readable (the
    // grant stands at the head), and the slice is the as-of-N set.
    let at_n = engine
        .dump_of_visible(&world_n, &|doc: &Address| head.world().readable(Some(B), doc))
        .into_string();
    assert!(at_n.contains(&secret_line()), "a grant after N opens the draft at /dump?at=N:\n{at_n}");
    let slice_n = format!("\"publication\": [{}]", quoted(&b.draft_a));
    assert!(at_n.contains(&slice_n), "the slice is the as-of-N set:\n{at_n}");
    assert!(!at_n.contains(&quoted(&draft_2)), "a draft minted after N is not in the N-world");

    // The same N-world at the N-world's OWN class would withhold it — which
    // is what the head predicate is chosen over.
    let own = engine
        .dump_of_visible(&world_n, &|doc: &Address| world_n.readable(Some(B), doc))
        .into_string();
    assert!(!own.contains(&secret_line()), "the N-world's own class has no grant yet");

    // The head, at B's class: both drafts in the slice (the second by the
    // account rung? no — B holds a grant on the first draft alone), so the
    // head's slice for B is the first draft, and for A both.
    let head_b = engine.world_dump_visible_to(Some(B)).into_string();
    assert!(head_b.contains(&slice_n), "B's head slice: the granted draft alone:\n{head_b}");
    let mut both = vec![quoted(&b.draft_a), quoted(&draft_2)];
    both.sort();
    let slice_a = format!("\"publication\": [{}]", both.join(", "));
    let head_a = engine.world_dump_visible_to(Some(A)).into_string();
    assert!(head_a.contains(&slice_a), "A's head slice: both drafts, address order:\n{head_a}");
}
