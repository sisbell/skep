//! The world dump at a READER'S CLASS (PUB round 2, lane 3.4 §3/§4), through
//! the assembled engine: the v5 format's two publication-round sections, and
//! the per-class post-filter over the harness-only walk — the same tree,
//! filtered by the threaded predicate before render. The daemon's suite
//! holds the wire oracle (H4: `/dump` equals this post-filter byte for byte);
//! what is tested here is the engine's own: the filter under the total
//! predicate IS the walk, the guest's publication section is empty, an
//! owner's lists its drafts, a grantee's follows the grant, a stranger's is
//! the guest's, each class is deterministic (PUB-8.26), and a historical world
//! dumps at the HEAD's class (PUB-6.48).

use crate::common;

use common::*;
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{Caller, Deposit};
use skep_content::Val;
use skep_engine::{Engine, Seq, World};
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
    let acct_a = delegated_account(engine, &node1(), BOOTSTRAP_PRINCIPAL, A);
    let (home_a, _) = ns.create_new_document(A, &acct_a, None).expect("A's published home");
    let (draft_a, _) = ns.create_new_document(A, &acct_a, None).expect("A's private draft");
    let acct_b = delegated_account(engine, &node1(), BOOTSTRAP_PRINCIPAL, B);
    let owner = Caller::Principal(A);
    engine
        .vstream()
        .insert(
            owner,
            &draft_a,
            vp(1, 1),
            vec![Val::new(SECRET.to_vec()), Val::new(vec![b'x'])],
            Deposit::Undeclared,
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
        .expect("the owner links within its draft");
    Board { acct_a, home_a, draft_a, link_a, acct_b }
}

/// A grant of `content_prefix` to `grantee`, issued by A from its doc 1.
fn grant(engine: &Engine, board: &Board, content_prefix: &Address, grantee: &Address) -> Address {
    grant_to(engine, board, content_prefix, vec![grantee.clone()])
}

/// [`grant`] with the `to` slot as DEPOSITED — empty for the ANY-PRINCIPAL
/// form (PUB-5.8), whose record has no grantee to name.
fn grant_to(engine: &Engine, board: &Board, content_prefix: &Address, to: Vec<Address>) -> Address {
    let issuer = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(issuer))
        .makelink(
            issuer,
            &board.home_a,
            SlotArg::Addrs(vec![content_prefix.clone()]),
            SlotArg::Addrs(to),
            SlotArg::Addrs(vec![t_grant()]),
        )
        .map(|(addr, _)| addr)
        .expect("the grant deposits into A's doc 1")
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
fn the_v5_format_renders_the_publication_and_grants_sections() {
    let engine = mem_engine();
    let board = board(&engine);
    let g = grant(&engine, &board, &board.draft_a, &board.acct_b);
    let text = engine.world_dump().into_string();

    assert!(text.starts_with("skep-world-dump v5\n"), "unexpected banner: {text:.32}");
    let publication = format!("\"publication\": [{}]", quoted(&board.draft_a));
    assert!(text.contains(&publication), "expected {publication} in:\n{text}");
    let grants = format!(
        "\"grants\": {{{}: {{\"content_prefix\": {}, \"grantee\": {}, \"home\": {}, \"issuer\": {}}}}}",
        quoted(&g),
        quoted(&board.draft_a),
        quoted(&board.acct_b),
        quoted(&board.home_a),
        quoted(&board.acct_a),
    );
    assert!(text.contains(&grants), "expected {grants} in:\n{text}");
    engine.check_hints().expect("the grant fold's seed equals its fold, through the section");
}

/// …and the section's OTHER rendered shape: the ANY-PRINCIPAL form (PUB-5.8)
/// has no grantee, and the record renders `none` in that field.
///
/// A shape the dump never renders is a hole in the oracle the crash and
/// conformance harnesses read it as, and one no comparison between two dumps
/// can see — both sides are rendered by the same builder, so both carry the
/// same hole. The section's four fields are the format, so each shape a
/// record can take is stated here rather than left to whichever world a
/// harness happens to run.
#[test]
fn the_grant_section_renders_an_any_principal_grant_with_no_grantee() {
    let engine = mem_engine();
    let board = board(&engine);
    let g = grant_to(&engine, &board, &board.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let text = engine.world_dump().into_string();

    let grants = format!(
        "\"grants\": {{{}: {{\"content_prefix\": {}, \"grantee\": none, \"home\": {}, \"issuer\": {}}}}}",
        quoted(&g),
        quoted(&board.draft_a),
        quoted(&board.home_a),
        quoted(&board.acct_a),
    );
    assert!(text.contains(&grants), "expected {grants} in:\n{text}");
    engine.check_hints().expect("the fold and its seed agree over a grantee-less record");
}

/// The filter under the TOTAL predicate is the harness-only walk, byte for
/// byte — the two are one tree rendered twice.
#[test]
fn the_filter_under_the_total_predicate_is_the_harness_walk() {
    let engine = mem_engine();
    let board = board(&engine);
    grant(&engine, &board, &board.draft_a, &board.acct_b);
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    assert_eq!(engine.dump_of_visible(world, &|_: &Address| true), engine.dump_of(world));
}

/// The GUEST (no principal): the publication section EMPTY, the exception-set
/// hint empty, no content line of the draft, no link of the draft in any
/// hint family — while the published home's grant and the namespace section
/// stay. A STRANGER principal — no account, no grant — reads exactly what the
/// guest reads.
#[test]
fn a_guest_s_dump_holds_no_draft_content_and_an_empty_publication_section() {
    let engine = mem_engine();
    let board = board(&engine);
    let g = grant(&engine, &board, &board.draft_a, &board.acct_b);

    let guest = engine.world_dump_visible_to(None).into_string();
    assert!(guest.starts_with("skep-world-dump v5\n"), "one banner for every class");
    assert!(
        guest.contains("\"publication\": []"),
        "the guest's publication section is EMPTY:\n{guest}"
    );
    assert!(guest.contains("\"publication.drafts\": {}"), "…and so is the hint:\n{guest}");
    assert!(!guest.contains(&secret_line()), "a draft's content line leaves:\n{guest}");
    assert!(!guest.contains(&quoted(&board.link_a)), "a draft's link leaves every hint:\n{guest}");
    assert!(guest.contains(&quoted(&g)), "the published home's grant link stays:\n{guest}");
    // The grant section is kept whole, so the draft the guest cannot open is
    // still named there, as that grant's `content_prefix` — the one dotted
    // rendering of it a guest's text carries. (The namespace section names it
    // too, but in the authoritative maps' tumbler form, not this one.)
    assert!(
        guest.contains(&quoted(&board.draft_a)),
        "the whole-kept grant section still names the draft:\n{guest}"
    );

    let stranger = engine.world_dump_visible_to(Some(STRANGER));
    assert_eq!(stranger.as_str(), guest, "a stranger's class is the guest's");
}

/// The OWNER lists its drafts and reads their content and links; the
/// GRANTEE follows the grant — before it, B's dump is the guest's; after it,
/// B's holds the draft's publication-section entry, content and link — and the
/// owner's and the grantee's dumps agree once both read the same set.
#[test]
fn an_owner_lists_its_drafts_and_a_grantee_follows_the_grant() {
    let engine = mem_engine();
    let board = board(&engine);

    let before = engine.world_dump_visible_to(Some(B));
    assert_eq!(before, engine.world_dump_visible_to(None), "ungranted, B reads as the guest");

    let owner = engine.world_dump_visible_to(Some(A)).into_string();
    let section = format!("\"publication\": [{}]", quoted(&board.draft_a));
    assert!(owner.contains(&section), "the owner's publication section lists its draft:\n{owner}");
    assert!(owner.contains(&secret_line()), "…with its content line:\n{owner}");
    assert!(owner.contains(&quoted(&board.link_a)), "…and its link in the hints:\n{owner}");

    grant(&engine, &board, &board.draft_a, &board.acct_b);
    let grantee = engine.world_dump_visible_to(Some(B)).into_string();
    assert!(
        grantee.contains(&section),
        "the grantee's publication section holds the granted draft:\n{grantee}"
    );
    assert!(grantee.contains(&secret_line()), "…and its content line:\n{grantee}");
    assert!(grantee.contains(&quoted(&board.link_a)), "…and its link:\n{grantee}");
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
        let board = board(&engine);
        grant(&engine, &board, &board.draft_a, &board.acct_b);
        engine
    };
    let (e1, e2) = (build(), build());
    for principal in [None, Some(A), Some(B), Some(STRANGER)] {
        let d1 = e1.world_dump_visible_to(principal);
        assert_eq!(d1, e1.world_dump_visible_to(principal), "{principal:?}: one world, one text");
        assert_eq!(
            d1,
            e2.world_dump_visible_to(principal),
            "{principal:?}: equal worlds, equal texts"
        );
    }
}

/// The historical shape (PUB-6.48, `/dump?at=N`'s two worlds): the N-world's
/// state, filtered at the HEAD's class. A grant committed AFTER N makes the
/// draft readable to B in the N-world's dump — its content line appears —
/// while the publication section is the AS-OF-N set: a second draft minted
/// after N is in the head's section and not in the N-world's.
#[test]
fn a_historical_world_dumps_at_the_head_s_class() {
    let dir = tempdir().expect("tempdir");
    let engine = Engine::open(fsync_cfg(dir.path())).expect("open");
    let board = board(&engine);
    let n: Seq = engine.kernel().current_seq();

    // After N: the grant, and a second draft.
    grant(&engine, &board, &board.draft_a, &board.acct_b);
    let (draft_two, _) =
        engine.namespace().create_new_document(A, &board.acct_a, None).expect("A's second draft");

    let head = engine.kernel().snapshot();
    let world_n = engine.world_at(n).expect("the N-world reconstructs");

    // The N-world at B's HEAD class: the draft's content is readable (the
    // grant stands at the head), and the publication section is the as-of-N
    // set.
    let at_n = engine
        .dump_of_visible(&world_n, &|doc: &Address| head.world().readable(Some(B), doc))
        .into_string();
    assert!(at_n.contains(&secret_line()), "a grant after N opens the draft at /dump?at=N:\n{at_n}");
    let first_draft_alone = format!("\"publication\": [{}]", quoted(&board.draft_a));
    assert!(
        at_n.contains(&first_draft_alone),
        "the publication section is the as-of-N set:\n{at_n}"
    );
    assert!(
        !at_n.contains(&quoted(&draft_two)),
        "…and B, which cannot read the later draft at the head either, sees none of it"
    );
    // …so the as-of-N claim is witnessed at a class that WOULD see the later
    // draft if the N-world held it: A reads both of its drafts at the head.
    let at_n_for_a = engine
        .dump_of_visible(&world_n, &|doc: &Address| head.world().readable(Some(A), doc))
        .into_string();
    assert!(
        at_n_for_a.contains(&first_draft_alone),
        "at A's head class the N-world's section still lists only the draft that existed at \
         N:\n{at_n_for_a}"
    );

    // The same N-world at the N-world's OWN class would withhold it — which
    // is what the head predicate is chosen over.
    let own = engine
        .dump_of_visible(&world_n, &|doc: &Address| world_n.readable(Some(B), doc))
        .into_string();
    assert!(!own.contains(&secret_line()), "the N-world's own class has no grant yet");

    // The head, at B's class: B holds a grant on the first draft alone, so
    // B's publication section lists that draft; A reads both, in address order.
    let head_b = engine.world_dump_visible_to(Some(B)).into_string();
    assert!(
        head_b.contains(&first_draft_alone),
        "B's head publication section: the granted draft alone:\n{head_b}"
    );
    let mut drafts = vec![quoted(&board.draft_a), quoted(&draft_two)];
    drafts.sort();
    let both_drafts = format!("\"publication\": [{}]", drafts.join(", "));
    let head_a = engine.world_dump_visible_to(Some(A)).into_string();
    assert!(
        head_a.contains(&both_drafts),
        "A's head publication section: both drafts, address order:\n{head_a}"
    );
}

/// The reach the dump's magnitude cost term rests on: a tumbler component is
/// a `Nat` with no magnitude bound, and the client — not the store — chooses
/// it. `makelink` gates neither slot's addresses against M3, so a grant may
/// name a `content_prefix` that was never minted and whose components are as
/// large as the depositor cares to make them; the grant fold admits the
/// record on its HOME alone, and the per-class filter keeps the grants
/// section WHOLE. So the invented address is rendered dotted, verbatim, to
/// every class including the guest.
///
/// A thirty-digit component, which no machine word holds, is enough to state
/// that the term is unbounded rather than to measure it.
#[test]
fn a_grant_names_an_address_the_client_invented() {
    let engine = mem_engine();
    let board = board(&engine);

    // A document-tier address under A's account whose ordinal M3 never
    // allocated and never could reach.
    let huge: Nat = "123456789012345678901234567890".parse().expect("a thirty-digit component");
    let invented: Address = {
        let comps = board.acct_a.tumbler().iter().cloned().chain([nat(0), huge]);
        validate(Tumbler::new(comps).expect("nonempty")).expect("a document tier address is T4-valid")
    };
    assert!(
        !engine.kernel().snapshot().world().m3().is_registered_document(&invented),
        "the point is an address M3 never minted"
    );

    grant(&engine, &board, &invented, &board.acct_b);

    let guest = engine.world_dump_visible_to(None).into_string();
    assert!(
        guest.contains(&quoted(&invented)),
        "the whole-kept grant section renders the invented address to the guest:\n{guest}"
    );
    assert!(
        guest.contains("123456789012345678901234567890"),
        "…component and all, at whatever magnitude the depositor chose"
    );
    // …and the grant is a real fold record, not a stray line: it opens
    // nothing, because no document lies under a prefix M3 never allocated.
    engine.check_hints().expect("the fold and its seed agree about the invented prefix");
}
