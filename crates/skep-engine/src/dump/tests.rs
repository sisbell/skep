use skep_address::{validate, Nat, Span};
use skep_arrangement::{Caller, Deposit, VPos, VSpec};
use skep_content::Val;
use skep_links::SlotArg;

use crate::testkit::{a_published_home_and_a_private_draft, delegated_account, mem_engine, USER};
use crate::Engine;

use super::*;

/// A content V-spec over `doc`: `width` positions of its content subspace
/// from `ordinal`. Shared with the `filter` submodule's tests, whose
/// open-surface deposits resolve slots through it.
pub(super) fn vspec(doc: &Address, ordinal: u32, width: u32) -> VSpec {
    let span = Span::new(
        Tumbler::new([Nat::from(1u32), Nat::from(ordinal)]).expect("nonempty"),
        Tumbler::new([Nat::from(0u32), Nat::from(width)]).expect("nonempty"),
    )
    .expect("well-formed test span");
    VSpec { source: doc.clone(), span }
}

pub(super) fn render_of(tree: &SerdeTree) -> String {
    tree.to_string()
}

/// An in-memory engine whose every slice holds something, driven through
/// the real drivers: an account and a document (M3), two content values
/// (M4, arranged by M5), and one link (M7) — the account off the crate's
/// `testkit`, and the mints and deposits this fixture's own, cut to
/// exactly what these tests read. Shared with the `filter` submodule's
/// tests, which need a world holding an entry in every family the
/// reduction reaches.
pub(super) fn populated_world() -> (Engine, World) {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    // A DRAFT (explicit `false`): the flagless first mint would be the
    // published home, which takes no in-place edit (PUB-2.11).
    let (doc, _) = engine
        .namespace()
        .create_new_document(USER, &acct, Some(false))
        .expect("the delegated owner may create a document");
    engine
        .vstream()
        .insert(
            Caller::Principal(USER),
            &doc,
            VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) },
            vec![Val::new(vec![b'a']), Val::new(vec![b'b'])],
            Deposit::Undeclared,
        )
        .expect("insert succeeds");
    engine
        .linkstore(&World::visible_to(Caller::Principal(USER)))
        .makelink(
            Caller::Principal(USER),
            &doc,
            SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
            SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
            SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
        )
        .expect("makelink succeeds");

    let world = engine.kernel().snapshot().world().clone();
    (engine, world)
}

/// The authoritative section renders EVERY slice: a world differing in
/// exactly one slice must render a different authoritative section, or the
/// harnesses' byte comparison is blind to that store. Only a test inside
/// the crate can pose the question, because only here can a world be built
/// one slice at a time.
#[test]
fn the_authoritative_section_renders_every_slice() {
    let (_engine, rich) = populated_world();
    let bare = World::genesis();
    let base = render_of(&authoritative_tree(&bare));

    for (slice, hybrid) in [
        ("namespace", World { namespace: rich.namespace.clone(), ..bare.clone() }),
        ("content", World { content: rich.content.clone(), ..bare.clone() }),
        ("arrangement", World { arrangement: rich.arrangement.clone(), ..bare.clone() }),
        ("links", World { links: rich.links.clone(), ..bare.clone() }),
    ] {
        assert_ne!(
            render_of(&authoritative_tree(&hybrid)),
            base,
            "the authoritative section ignores the {slice} slice"
        );
    }
}

/// The term that dominates a dump's cost, pinned where the cost is
/// claimed: a content byte is a whole serialized ELEMENT, not a byte of a
/// blob. serde has no byte specialization for `[u8]`, so M4's `Val` walks
/// the data model through `serialize_seq` — one integer node per byte —
/// and a world holding N bytes of content transcodes into a tree with N
/// nodes in it before a byte of text is written. The transcode's `Bytes`
/// arm exists and says the opposite at a glance, which is exactly why the
/// ratio [`crate::Engine::dump_of`] states is a test and not a sentence.
#[test]
fn a_content_byte_costs_a_whole_tree_node() {
    let payload: Vec<u8> = (0..64u8).collect();
    let SerdeTree::Seq(nodes) = to_tree(&Val::new(payload.clone())) else {
        panic!("a content value transcodes as a sequence, not as a byte blob")
    };
    assert_eq!(nodes.len(), payload.len(), "one tree node per content byte");
    assert!(
        nodes.iter().all(|n| matches!(n, SerdeTree::U64(_))),
        "every content byte arrives as its own integer element"
    );

    // …and the text is proportional to the same term: decimal digits and
    // separators per byte, never the two hex characters the `Bytes` arm
    // would have written.
    let text = render_of(&to_tree(&Val::new(vec![255u8; 4])));
    assert_eq!(text, "[255, 255, 255, 255]");
}

/// The hint check's rebuild runs FROM SCRATCH, and that is what makes it an
/// oracle over a LIVE world: a fold that drifted leaves its index POPULATED
/// and wrong, never empty. The integration suite's
/// `the_hint_check_refuses_a_world_whose_derived_state_was_never_rebuilt`
/// holds the EMPTY case — a decoded world, every derived index empty — and a
/// rebuild that re-seeded only an EMPTY index would go on refusing that
/// world while passing every drifted one it is handed, every recovered
/// world M2's crash harness ends a full-depth judgment on among them. So
/// each engine index is drifted here while it stays populated: the
/// exception set one entry wider than M3's publication map, and a grant
/// fold holding a record this world's links never deposited.
#[test]
fn the_hint_check_refuses_a_populated_index_that_drifted_from_its_rebuild() {
    let (engine, world) = populated_world();
    engine.check_hints_of(&world).expect("the premise: the populated world is faithful");

    // The exception set, one entry wider: a document-tier address under the
    // draft's own owner that no mint produced, memoized beside the draft.
    let owner = world.drafts().next().expect("the fixture's draft").owner_account.clone();
    let comps = owner.tumbler().iter().cloned().chain([Nat::from(0u32), Nat::from(99u32)]);
    let phantom = validate(Tumbler::new(comps).expect("nonempty"))
        .expect("a document-tier address under the owner is T4-valid");
    let wider = World { drafts: world.drafts.update(phantom, owner), ..world.clone() };
    engine
        .check_hints_of(&wider)
        .expect_err("an exception set one entry wider than its rebuild must fail the check");

    // The grant fold, holding a record of ANOTHER world's: an admitted
    // grant deposited through a second engine, carried over whole.
    let (granting, home, draft) = a_published_home_and_a_private_draft();
    let caller = Caller::Principal(USER);
    granting
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            &home,
            SlotArg::Addrs(vec![draft]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![crate::types::t_grant().clone()]),
        )
        .expect("a grant in the issuer's own doc 1");
    let granted = granting.kernel().snapshot().world().clone();
    assert_eq!(granted.universal_grants().len(), 1, "the premise: the grant is admitted");
    let foreign = World { grants: granted.grants.clone(), ..world.clone() };
    engine
        .check_hints_of(&foreign)
        .expect_err("a grant fold its links never deposited must fail the check");
}

fn divergence(live: &str, rebuilt: &str) -> HintDivergence {
    HintDivergence {
        live: WorldDump(live.to_owned()),
        rebuilt: WorldDump(rebuilt.to_owned()),
    }
}

/// The report a real divergence produces — the one text a harness prints
/// when the check finds what it exists to find: it names the byte the two
/// renderings first disagree on and shows both sides around it.
#[test]
fn a_hint_divergence_localizes_the_first_differing_byte() {
    let rendered = divergence("hints: [a, b]", "hints: [a, c]").to_string();
    assert!(rendered.contains("byte 11"), "the offset must be named: {rendered}");
    assert!(
        rendered.contains("hints: [a, b]") && rendered.contains("hints: [a, c]"),
        "both renderings must be shown: {rendered}"
    );
}

/// …and it survives the strings a real divergence carries: a difference
/// inside multibyte text, where a fixed-width window lands mid-character
/// at both ends; one at the very first byte; and one where a rendering is
/// a strict prefix of the other, so there is no differing byte at all and
/// the shorter length is the offset.
#[test]
fn a_hint_divergence_report_survives_multibyte_and_prefix_cases() {
    let snow = "☃".repeat(20);

    let live = format!("{snow}abc{snow}");
    let rebuilt = format!("{snow}abd{snow}");
    let rendered = divergence(&live, &rebuilt).to_string();
    assert!(rendered.contains("byte 62"), "the offset must be named: {rendered}");

    let rendered = divergence(&snow, &format!("z{snow}")).to_string();
    assert!(rendered.contains("byte 0"), "the offset must be named: {rendered}");

    let rendered = divergence("ab", &format!("abx{}", "🌍".repeat(20))).to_string();
    assert!(rendered.contains("byte 2"), "a prefix diverges at its own end: {rendered}");
}

/// …and the OTHER carrier localizes too. `Result::expect` and `unwrap`
/// print `Debug`, which is how every caller of `check_hints` in this
/// workspace meets a divergence, and a rendering costs a tree node per
/// content byte — so a `Debug` that carried the two dumps would put two
/// whole worlds of escaped text on one line. The size assertion is the
/// claim: the report is smaller than ONE rendering, where carrying them
/// would make it larger than two.
#[test]
fn a_hint_divergence_debugs_as_its_localization_and_not_as_two_worlds() {
    let filler = "a, ".repeat(4096);
    let (live, rebuilt) = (format!("hints: [{filler}b]"), format!("hints: [{filler}c]"));
    let at = "hints: [".len() + filler.len();

    let rendered = format!("{:?}", divergence(&live, &rebuilt));
    assert!(
        rendered.contains(&format!("at_byte: {at}")),
        "the offset must be named: {rendered:.160}"
    );
    assert!(
        rendered.contains("b]") && rendered.contains("c]"),
        "both sides must be shown around it: {rendered:.160}"
    );
    assert!(
        rendered.len() < live.len(),
        "the report carried the renderings: {} bytes for two dumps of {} each",
        rendered.len(),
        live.len()
    );
}
