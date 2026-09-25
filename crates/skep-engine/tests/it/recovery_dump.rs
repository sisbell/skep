//! The world-dump surface and the recovery-order contract, together: what the
//! dump SHOWS (one test per hint family, each pinned to its rendered text,
//! because the dump is the crash harness's oracle and an entry that renders
//! empty is a hole in it), dump determinism (two engines that ran the same
//! history render byte-identically), recovery equivalence (a world folded live
//! from genesis dumps byte-equal to the world restored from checkpoint +
//! rebuild_derived + replay, with the checkpoint taken both before and after
//! the links exist), and hint faithfulness (live incrementally-maintained
//! hints equal a from-authoritative rebuild) — with the faithfulness check's
//! own power to refuse a world whose hints were never rebuilt.

use crate::common;

use common::*;
use skep_address::Address;
use skep_arrangement::Deposit;
use skep_content::Val;
use skep_engine::{Engine, World};
use skep_kernel::TxnError;
use skep_links::{enc, HasLinks, NullifyError, ReservedAddrs, ShippedType, SlotArg};
use tempfile::tempdir;

/// The shipped class ordinary emissions land in: `PredDef`, the first Unary
/// idem⊤ class (the registry's population is the compiled shipped five —
/// owner ruling, 2026-08-26 — so there is no app class to enrich a config
/// with, and no config).
fn pred_def_ty() -> skep_links::Endset {
    enc(std::slice::from_ref(&ReservedAddrs::format().pred_def))
}

/// The links one populated world holds — one of each kind the dump's hints
/// section projects. `sup_old` and `sup_new` are the two ends of the
/// supersession claim, in M7's own slot order (F holds the OLD link; edges run
/// old → new); `nullified` is the link the retraction nullifies.
struct Deposited {
    sup_old: Address,
    sup_new: Address,
    nullified: Address,
    sup_claim: Address,
    retraction: Address,
    emitted: Address,
}

impl Deposited {
    /// Every link deposited, whatever its kind.
    fn all(&self) -> Vec<&Address> {
        vec![
            &self.sup_old,
            &self.sup_new,
            &self.nullified,
            &self.sup_claim,
            &self.retraction,
            &self.emitted,
        ]
    }
}

/// Deposit one of every hint family the dump can show, through the real write
/// surfaces: three links over the document's content, a supersession claim
/// over two of them, a retraction of the third, and one managed emission
/// under the shipped `PredDef` class. `start` is the first I-address the
/// document's content occupies, which the emission points from.
fn deposit_every_hint_family(engine: &Engine, doc: &Address, start: &Address) -> Deposited {
    // Every write below is the OWNER's, at the owner's own visibility class.
    let visibility = World::visible_to(OWNER);
    let make_link = |from: (u32, u32), to: (u32, u32)| {
        engine
            .linkstore(&visibility)
            .makelink(
                OWNER,
                doc,
                SlotArg::Resolve(vec![vspec(doc, from.0, from.1)]),
                SlotArg::Resolve(vec![vspec(doc, to.0, to.1)]),
                SlotArg::Resolve(vec![vspec(doc, 1, 2)]),
            )
            .expect("makelink succeeds")
            .0
    };
    let sup_old = make_link((1, 1), (2, 1));
    let sup_new = make_link((2, 1), (1, 1));
    let nullified = make_link((1, 2), (1, 1));
    let (sup_claim, _) = engine
        .linkstore(&visibility)
        .assert_sup(OWNER, doc, &sup_old, &sup_new)
        .expect("assert_sup");
    let (retraction, _) =
        engine.linkstore(&visibility).nullify(OWNER, doc, &nullified).expect("nullify");
    let (emitted, _) = engine
        .linkstore(&visibility)
        .emit(OWNER, doc, &pred_def_ty(), start, &[])
        .expect("pred_def-typed emit");
    Deposited { sup_old, sup_new, nullified, sup_claim, retraction, emitted }
}

/// An in-memory world with every dump-observable hint family populated, and
/// its rendering. Each test builds its own, so none shares state with its
/// neighbours.
fn populated_dump() -> (String, Deposited) {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (_acct, doc) = setup_draft(&engine);
    let (start, _) = engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])], Deposit::Undeclared)
        .expect("insert succeeds");
    let deposited = deposit_every_hint_family(&engine, &doc, &start);
    (engine.world_dump().into_string(), deposited)
}

/// One hints entry, rendered exactly. The dump IS the harnesses' oracle, so an
/// entry that goes empty — or renders something else — is a hole in it that
/// every dump-to-dump comparison stays green through.
fn assert_entry(text: &str, key: &str, value: &str) {
    let needle = format!("{key:?}: {value}");
    assert!(text.contains(&needle), "expected {needle} in the dump:\n{text}");
}

/// One type class's rendering where its two views PART: its audit and active
/// slices — LINK addresses, which is what a typed slice holds — and its key.
fn class_of_views(audit: &[&Address], active: &[&Address], key: &str) -> String {
    let (audit, active) = (seq_of(audit), seq_of(active));
    format!("{{\"active\": {active}, \"audit\": {audit}, \"key\": [{key:?}]}}")
}

/// …and where they agree, as they do for every class no retraction touches.
fn class_of(links: &[&Address], key: &str) -> String {
    class_of_views(links, links, key)
}

#[test]
fn the_dump_lists_every_deposited_link_in_the_audit_slice() {
    let (text, deposited) = populated_dump();
    assert_entry(&text, "links.audit", &seq_of(&deposited.all()));
}

#[test]
fn the_dump_drops_a_nullified_link_from_the_active_slice() {
    let (text, deposited) = populated_dump();
    let live: Vec<&Address> =
        deposited.all().into_iter().filter(|a| *a != &deposited.nullified).collect();
    assert_entry(&text, "links.active", &seq_of(&live));
}

#[test]
fn the_dump_names_the_nullified_set() {
    let (text, deposited) = populated_dump();
    assert_entry(&text, "links.nullified", &seq_of(&[&deposited.nullified]));
}

#[test]
fn the_dump_carries_the_supersession_forward_edges() {
    let (text, deposited) = populated_dump();
    // The claim is the edge's, not the claimant's: the one forward edge in the
    // graph runs out of the superseded link, and the claim itself is not on it.
    let edges = format!("{{{}: {}}}", quoted(&deposited.sup_old), seq_of(&[&deposited.sup_new]));
    assert_entry(&text, "supersession", &edges);
}

/// A draft of [`OWNER`]'s with two content values and two links over them —
/// the endpoints a supersession claim runs between. Returns `(doc, old, new)`.
fn a_draft_with_two_links(engine: &Engine) -> (Address, Address, Address) {
    let (_acct, doc) = setup_draft(engine);
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])], Deposit::Undeclared)
        .expect("insert succeeds");
    let visibility = World::visible_to(OWNER);
    let make_link = |from: u32, to: u32| {
        engine
            .linkstore(&visibility)
            .makelink(
                OWNER,
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, from, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, to, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink succeeds")
            .0
    };
    let (old, new) = (make_link(1, 2), make_link(2, 1));
    (doc, old, new)
}

/// A retracted ENDPOINT leaves its edges operative — Df-SUCC reads the CLAIM's
/// activity and never the endpoint's (M7's EL14e) — so the supersession
/// family carries an edge out of a nullified link. The populated world's one
/// edge runs out of an ACTIVE link, where a family walking the active slice
/// for edges answers alike; here it would drop the edge, and every
/// dump-to-dump comparison would stay green, since both sides are rendered by
/// the same builder.
#[test]
fn the_dump_carries_a_supersession_edge_out_of_a_retracted_link() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (doc, old, new) = a_draft_with_two_links(&engine);
    let visibility = World::visible_to(OWNER);
    engine.linkstore(&visibility).assert_sup(OWNER, &doc, &old, &new).expect("assert_sup");
    engine.linkstore(&visibility).nullify(OWNER, &doc, &old).expect("retract the OLD endpoint");

    let text = engine.world_dump().into_string();
    assert_entry(&text, "links.nullified", &seq_of(&[&old]));
    assert_entry(&text, "supersession", &format!("{{{}: {}}}", quoted(&old), seq_of(&[&new])));
    engine.check_hints().expect("the rebuild renders the same edge");
}

/// …and the other half of Df-SUCC: a retracted CLAIM asserts no edge, so the
/// family carries none out of the link it named. A family built from the
/// supersession class's claims without the nullified filter passes every
/// other fixture here, and `check_hints` with them; the per-class filter keys
/// an edge by its OPERATIVE claims, so it would drop that edge under the
/// total predicate.
#[test]
fn a_retracted_supersession_claim_carries_no_edge() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (doc, old, new) = a_draft_with_two_links(&engine);
    let visibility = World::visible_to(OWNER);
    let (claim, _) =
        engine.linkstore(&visibility).assert_sup(OWNER, &doc, &old, &new).expect("assert_sup");
    engine.linkstore(&visibility).nullify(OWNER, &doc, &claim).expect("retract the CLAIM");

    let text = engine.world_dump().into_string();
    assert_entry(&text, "links.nullified", &seq_of(&[&claim]));
    assert_entry(&text, "supersession", "{}");
    let snap = engine.kernel().snapshot();
    assert_eq!(
        engine.dump_of_visible(snap.world(), &|_: &Address| true),
        engine.dump_of(snap.world()),
        "the per-class filter under the total predicate is the harness-only walk"
    );
    engine.check_hints().expect("the rebuild renders no edge either");
}

/// `links.nullified` is the WHOLE tombstone set only because `nullify` admits
/// no target but a resident link or the address its own retraction will
/// occupy (`hints_tree`); a root that is no link would sit in M7's hint and
/// outside this rendering and outside what `check_hints` certifies. M7 holds a
/// wider retraction as a deferred scope decision, so the gate is pinned where
/// its widening would first cost the oracle.
#[test]
fn the_nullified_family_is_the_whole_tombstone_set_because_only_links_are_retracted() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (_acct, doc) = setup_draft(&engine);
    let (position, _) = engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p'])], Deposit::Undeclared)
        .expect("insert succeeds");
    let visibility = World::visible_to(OWNER);
    for (what, target) in [("the document", &doc), ("a content position", &position)] {
        assert!(
            matches!(
                engine.linkstore(&visibility).nullify(OWNER, &doc, target),
                Err(TxnError::Rejected(NullifyError::BadTarget))
            ),
            "{what} is no link: its retraction would tombstone a root the family never renders"
        );
    }
    let own_address = element(&doc, 2, 1); // the draft's first link address
    let (retraction, _) = engine
        .linkstore(&visibility)
        .nullify(OWNER, &doc, &own_address)
        .expect("a retraction of the address it will itself occupy");
    assert_eq!(retraction, own_address, "born nullified: the retraction is its own target");
    let text = engine.world_dump().into_string();
    assert_entry(&text, "links.audit", &seq_of(&[&retraction]));
    assert_entry(&text, "links.active", "[]");
    assert_entry(&text, "links.nullified", &seq_of(&[&retraction]));
    engine.check_hints().expect("the rebuild renders the same tombstones");
}

#[test]
fn the_dump_names_every_shipped_class_with_its_typed_slices() {
    let (text, deposited) = populated_dump();
    for (label, ordinal, links) in [
        ("shipped.pred_def", 1, vec![&deposited.emitted]),
        ("shipped.pred_stable", 2, Vec::new()),
        ("shipped.retired", 3, Vec::new()),
        ("shipped.supersedes", 4, vec![&deposited.sup_claim]),
        ("shipped.retraction", 5, vec![&deposited.retraction]),
    ] {
        assert_entry(&text, label, &class_of(&links, &format!("1.1.0.1.0.1.0.1.{ordinal}")));
    }
}

/// M9 owns no slice — its definition registry IS these M7 tuples — so the four
/// projections are what a harness sees of it: the pred_def emission above IS
/// a registration tuple, and the stable projections stay empty. Their
/// PRESENCE is what makes a later loss visible.
#[test]
fn the_dump_projects_the_predicate_registry() {
    let (text, _deposited) = populated_dump();
    let start = quoted(&addr(&[1, 0, 1, 0, 1, 0, 1, 1]));
    for entry in ["predicates.defs.audit", "predicates.defs.active"] {
        assert_entry(&text, entry, &format!("[{start}]"));
    }
    for entry in ["predicates.stable.audit", "predicates.stable.active"] {
        assert_entry(&text, entry, "[]");
    }
}

/// The ACTIVE half of the dump's two view-split families, seen to part from
/// the AUDIT half. Every other fixture here retracts an ORDINARY link, so each
/// shipped class's two slices, and each predicate projection's two rows,
/// render alike in it — and a builder that read the audit view under both
/// labels would pass every assertion in this file while the faithfulness
/// check stopped reaching M7's active-view typed slices and member sets. Here
/// two `pred_stable` tuples register two members and the first is RETRACTED:
/// it stays in its class's audit slice and leaves the active one, and its
/// member stays in the audit projection and leaves the active one, no active
/// tuple asserting it. The retraction is an active tuple of its own class, so
/// the active half is also seen non-empty.
#[test]
fn a_shipped_class_s_active_slice_and_active_projection_render_the_active_view() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (_acct, draft) = setup_draft(&engine);
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    let visibility = World::visible_to(OWNER);
    let register = |member: &Address| {
        engine
            .linkstore(&visibility)
            .emit(OWNER, &draft, &pred_stable, member, &[])
            .expect("a pred_stable tuple in the owner's own draft")
            .0
    };
    let (retracted_member, kept_member) = (element(&draft, 1, 1), element(&draft, 1, 2));
    let (retracted, kept) = (register(&retracted_member), register(&kept_member));
    let (retraction, _) = engine
        .linkstore(&visibility)
        .nullify(OWNER, &draft, &retracted)
        .expect("the owner retracts its own tuple");

    let text = engine.world_dump().into_string();
    assert_entry(
        &text,
        "shipped.pred_stable",
        &class_of_views(&[&retracted, &kept], &[&kept], "1.1.0.1.0.1.0.1.2"),
    );
    assert_entry(&text, "predicates.stable.audit", &seq_of(&[&retracted_member, &kept_member]));
    assert_entry(&text, "predicates.stable.active", &seq_of(&[&kept_member]));
    assert_entry(&text, "shipped.retraction", &class_of(&[&retraction], "1.1.0.1.0.1.0.1.5"));
    engine.check_hints().expect("a rebuild renders both views as the live world does");
}

/// The determinism clause, stated over EQUAL WORLDS rather than one world: two
/// engines that ran the same history render byte-identically, though each
/// holds its exception set in an `im::HashMap` under its own `RandomState`, so
/// the two iterate it in different orders. That hash-ordered index is what the
/// transcode's map sort exists for; the store slices serialize in key order at
/// their own `Serialize`.
#[test]
fn two_engines_with_the_same_history_dump_byte_equal() {
    /// Four drafts in one account — the explicit-`false` first mint and three
    /// flagless ones after it — content in each, and every hint family in the
    /// first: enough distinct hashed keys in the exception set that two
    /// coincidentally equal iteration orders are not the explanation.
    fn scripted() -> Engine {
        let engine = Engine::open(mem_cfg()).expect("in-memory open");
        let (acct, doc) = setup_draft(&engine);
        let (start, _) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])], Deposit::Undeclared)
            .expect("insert succeeds");
        deposit_every_hint_family(&engine, &doc, &start);
        for byte in [b'r', b's', b't'] {
            let (d, _) = engine
                .namespace()
                .create_new_document(USER, &acct, None)
                .expect("the delegated owner may create a document");
            engine
                .vstream()
                .insert(OWNER, &d, vp(1, 1), vec![Val::new(vec![byte])], Deposit::Undeclared)
                .expect("insert succeeds");
        }
        engine
    }

    assert_eq!(
        scripted().world_dump(),
        scripted().world_dump(),
        "two engines that ran one history must render one text"
    );
}

/// Recovery equivalence with the checkpoint taken BELOW the links: the reopen
/// restores a content-only checkpoint and replays the whole link history onto
/// it, so what is pinned here is that the incremental fold reproduces the live
/// world exactly.
#[test]
fn a_world_replayed_onto_a_content_only_checkpoint_dumps_byte_equal_to_the_live_fold() {
    let dir = tempdir().expect("tempdir");

    let dump_live;
    {
        let engine =
            Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let (_acct, doc) = setup_draft(&engine);

        // History batch A (below the checkpoint): content.
        let (start, _) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])], Deposit::Undeclared)
            .expect("insert succeeds");

        // Checkpoint mid-history, so recovery is checkpoint + replay, not a
        // pure journal fold.
        engine.kernel().checkpoint().expect("checkpoint succeeds");

        // History batch B (the replay tail): every hint family, past the
        // checkpoint.
        deposit_every_hint_family(&engine, &doc, &start);

        let d1 = engine.world_dump();
        let d2 = engine.world_dump();
        assert_eq!(d1, d2, "two dumps of one world must be byte-equal");

        engine.check_hints().expect("live hints match a from-scratch rebuild");

        dump_live = d1;
        // Engine drops: journal lock released.
    }

    {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen");

        let dump_recovered = engine.world_dump();
        assert_eq!(
            dump_live, dump_recovered,
            "a world folded live and a world restored from checkpoint+replay must dump byte-equal"
        );

        engine.check_hints().expect("recovered hints match a from-scratch rebuild");
    }
}

/// The recovery the world actually has to survive: a checkpoint taken with the
/// links already resident, so the reopen deserializes M7's slice with its
/// skip-serialized hints gone, rebuilds them from the authoritative links map,
/// and only then replays the tail. The other
/// equivalence test checkpoints below the first link, so its rebuild runs over
/// an empty map and says nothing about this one.
#[test]
fn recovery_rebuilds_hints_from_a_checkpoint_that_already_holds_links() {
    let dir = tempdir().expect("tempdir");

    let dump_live;
    {
        let engine =
            Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let (_acct, doc) = setup_draft(&engine);
        let (start, _) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])], Deposit::Undeclared)
            .expect("insert succeeds");
        deposit_every_hint_family(&engine, &doc, &start);

        // LOAD-BEARING: the checkpoint sits ABOVE every link, so the recovered
        // base is a world whose hints must be rebuilt rather than replayed.
        engine.kernel().checkpoint().expect("checkpoint succeeds");

        // A short replay tail above it, so recovery is genuinely base + fold.
        engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 3), vec![Val::new(vec![b'r'])], Deposit::Undeclared)
            .expect("insert succeeds");

        dump_live = engine.world_dump();
    }

    {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen");
        assert_eq!(
            dump_live,
            engine.world_dump(),
            "hints rebuilt from a checkpoint that already held links must equal the live fold"
        );
        engine.check_hints().expect("rebuilt hints match a from-scratch rebuild");
    }
}

/// A world `Engine::world_at` reconstructed is a root a kernel can be opened
/// on: `Durability::InMemory` never runs `rebuild_derived`, so a reconstruction
/// must arrive with its hints already faithful.
#[test]
fn a_reconstructed_historical_world_carries_faithful_hints() {
    let dir = tempdir().expect("tempdir");
    let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
    let (_acct, doc) = setup_draft(&engine);
    let (start, _) = engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])], Deposit::Undeclared)
        .expect("insert succeeds");

    let past = engine.kernel().current_seq();
    deposit_every_hint_family(&engine, &doc, &start);

    let world = engine.world_at(past).expect("a committed boundary answers");
    engine.check_hints_of(&world).expect("a reconstructed world's hints match a rebuild");
    assert_ne!(
        engine.dump_of(&world),
        engine.world_dump(),
        "the reconstruction must be of the PAST, not of the head"
    );
}

/// A world the caller pinned itself — a snapshot rather than the engine's
/// own committed read — dumps deterministically and its hints are faithful:
/// the render takes nothing from the engine but the world it is handed, so a
/// harness may pin any world and render it when it likes. That is asked of a
/// SECOND engine as well, one that never saw this world: it renders the same
/// bytes and passes the same check, so nothing of the handle a caller asks
/// through reaches either answer.
#[test]
fn a_caller_pinned_world_dumps_deterministically() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (_acct, doc) = setup_draft(&engine);
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'v'])], Deposit::Undeclared)
        .expect("insert succeeds");

    let snap = engine.kernel().snapshot();
    let d1 = engine.dump_of(snap.world());
    let d2 = engine.dump_of(snap.world());
    assert_eq!(d1, d2);
    engine.check_hints_of(snap.world()).expect("hints are faithful");

    let unrelated = Engine::open(mem_cfg()).expect("a second in-memory open");
    assert_eq!(unrelated.dump_of(snap.world()), d1, "a world renders alike through any engine");
    unrelated.check_hints_of(snap.world()).expect("…and checks alike through any engine");
}

/// The hint check's OWN power. Every other `check_hints`/`check_hints_of` in
/// this suite expects `Ok`, so a check that could not answer `Err` — one that
/// returned `Ok` outright, or compared a world with itself — would leave every
/// one of them green. Held over the world `World`'s invariant note names as
/// outside the invariant: decoded from bytes, its authoritative slices the
/// live world's and its derived state never rebuilt. The check must refuse
/// it, report that world's rendering beside what a rebuild of those slices
/// renders — which is the live world's — and find their first difference past
/// the authoritative section, since a rebuild moves derived state alone.
#[test]
fn the_hint_check_refuses_a_world_whose_derived_state_was_never_rebuilt() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (_acct, draft) = setup_draft(&engine);
    let (start, _) = engine
        .vstream()
        .insert(OWNER, &draft, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])], Deposit::Undeclared)
        .expect("insert succeeds");
    let deposited = deposit_every_hint_family(&engine, &draft, &start);
    let live = engine.kernel().snapshot().world().clone();
    let bytes = bincode::serialize(&live).expect("a world serializes");
    let unrebuilt: World = bincode::deserialize(&bytes).expect("this build's own bytes decode");

    // The premise, in both of the directions the invariant note gives: the
    // empty exception set reads the draft PUBLISHED, and M7's empty hints read
    // a retracted link ACTIVE.
    assert!(!live.readable(None, &draft), "live: the draft is private");
    assert!(unrebuilt.readable(None, &draft), "unrebuilt: the empty set reads the draft published");
    assert!(!live.links().is_active(&deposited.nullified), "live: the retracted link is inactive");
    assert!(
        unrebuilt.links().is_active(&deposited.nullified),
        "unrebuilt: the empty tombstone set reads the retracted link active"
    );

    let err = engine
        .check_hints_of(&unrebuilt)
        .expect_err("a world with no derived state must fail the check");
    assert_eq!(err.live, engine.dump_of(&unrebuilt), "the live side is the checked world's rendering");
    assert_eq!(err.rebuilt, engine.dump_of(&live), "the rebuilt side is what the live world renders");
    let at = err
        .live
        .as_bytes()
        .iter()
        .zip(err.rebuilt.as_bytes())
        .position(|(l, r)| l != r)
        .expect("the renderings differ within their common length");
    let derived_start = err.live.as_str().find("\"grants\": ").expect("the first derived section");
    assert!(
        at > derived_start,
        "the first difference, at byte {at}, lies in an authoritative slice"
    );
}

/// The dump's vocabulary is part of its format, so it is pinned here rather
/// than left to whatever the assembler happens to call its fields: each slice
/// of the authoritative section is named for the store it belongs to, and the
/// banner names the version those keys belong to.
#[test]
fn the_dump_names_each_slice_of_the_authoritative_section_for_its_store() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let text = engine.world_dump().into_string();

    assert!(text.starts_with("skep-world-dump v5\n"), "unexpected banner: {text:.32}");
    // M7's own serde field shares the `links` slice's name, so that key is
    // pinned in front of the field: a bare `"links"` would be found inside the
    // slice whatever the slice itself were called.
    for slice in [r#""namespace""#, r#""content""#, r#""arrangement""#, r#""links": {"links": "#] {
        assert!(text.contains(slice), "the authoritative slice {slice} must be named: {text:.200}");
    }
    // v5 (lane 3.4): M3's publication map and the grant fold's operative
    // set are sections of their own, beside the hints' copy of the set.
    for key in [r#""publication": ["#, r#""grants": {"#, r#""publication.drafts": {"#] {
        assert!(text.contains(key), "the v5 key {key} must be named: {text:.400}");
    }
}

/// A dump is its text, and every way of reading it out gives the same text —
/// so a caller showing one reaches for `{}` rather than an accessor, and
/// equal dumps hash alike for a harness collecting the distinct ones across a
/// sweep of crash points.
#[test]
fn a_dump_reads_out_as_its_text_by_every_route() {
    use std::collections::HashSet;

    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let dump = engine.world_dump();

    assert_eq!(format!("{dump}"), dump.as_str());
    assert_eq!(AsRef::<str>::as_ref(&dump), dump.as_str());
    assert_eq!(dump.as_bytes(), dump.as_str().as_bytes());

    let distinct: HashSet<_> = [engine.world_dump(), engine.world_dump()].into_iter().collect();
    assert_eq!(distinct.len(), 1, "two dumps of one world are one dump");
    assert_eq!(dump.clone().into_string(), dump.as_str());
}
