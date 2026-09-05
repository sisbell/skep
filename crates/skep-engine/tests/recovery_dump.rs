//! The world-dump surface and the recovery-order contract, together: what the
//! dump SHOWS (one test per hint family, each pinned to its rendered text,
//! because the dump is the crash harness's oracle and an entry that renders
//! empty is a hole in it), dump determinism (two engines that ran the same
//! history render byte-identically), recovery equivalence (a world folded live
//! from genesis dumps byte-equal to the world restored from checkpoint +
//! rebuild_derived + replay, with the checkpoint taken both before and after
//! the links exist), and hint faithfulness (live incrementally-maintained
//! hints equal a from-authoritative rebuild).

#![cfg(feature = "dump")]

mod common;

use common::*;
use skep_address::Address;
use skep_content::Val;
use skep_engine::{Engine, ReservedAddrs};
use skep_links::{enc, SlotArg};
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
fn every_hint_family(engine: &Engine, doc: &Address, start: &Address) -> Deposited {
    let make_link = |from: (u32, u32), to: (u32, u32)| {
        engine
            .linkstore()
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
    let (sup_claim, _) =
        engine.linkstore().assert_sup(OWNER, doc, &sup_old, &sup_new).expect("assert_sup");
    let (retraction, _) = engine.linkstore().nullify(OWNER, doc, &nullified).expect("nullify");
    let (emitted, _) = engine
        .linkstore()
        .emit(OWNER, doc, &pred_def_ty(), start, &[])
        .expect("pred_def-typed emit");
    Deposited { sup_old, sup_new, nullified, sup_claim, retraction, emitted }
}

/// An in-memory world with every dump-observable hint family populated, and
/// its rendering. Each test builds its own, so none shares state with its
/// neighbours.
fn populated_dump() -> (String, Deposited) {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (_acct, doc) = setup_doc(&engine);
    let (start, _) = engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])])
        .expect("insert succeeds");
    let deposited = every_hint_family(&engine, &doc, &start);
    (engine.world_dump().into_string(), deposited)
}

/// One hints entry, rendered exactly. The dump IS the harnesses' oracle, so an
/// entry that goes empty — or renders something else — is a hole in it that
/// every dump-to-dump comparison stays green through.
fn assert_entry(text: &str, key: &str, value: &str) {
    let needle = format!("{key:?}: {value}");
    assert!(text.contains(&needle), "expected {needle} in the dump:\n{text}");
}

/// One address as the dump renders it: dotted decimal, quoted.
fn quoted(addr: &Address) -> String {
    format!("{:?}", addr.to_string())
}

/// An address sequence as the dump renders it: address-ordered, since every
/// hint it reads is an ordered set.
fn seq_of(addrs: &[&Address]) -> String {
    let mut sorted = addrs.to_vec();
    sorted.sort();
    let rendered: Vec<String> = sorted.iter().map(|a| quoted(a)).collect();
    format!("[{}]", rendered.join(", "))
}

/// One type class's rendering: its audit and active slices and its key.
fn class_of(members: &[&Address], key: &str) -> String {
    let m = seq_of(members);
    format!("{{\"active\": {m}, \"audit\": {m}, \"key\": [{:?}]}}", key)
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

#[test]
fn the_dump_names_every_shipped_class_with_its_typed_slices() {
    let (text, deposited) = populated_dump();
    for (label, ordinal, members) in [
        ("shipped.pred_def", 1, vec![&deposited.emitted]),
        ("shipped.pred_stable", 2, Vec::new()),
        ("shipped.retired", 3, Vec::new()),
        ("shipped.supersedes", 4, vec![&deposited.sup_claim]),
        ("shipped.retraction", 5, vec![&deposited.retraction]),
    ] {
        assert_entry(&text, label, &class_of(&members, &format!("1.1.0.1.0.1.0.1.{ordinal}")));
    }
}

/// M9 owns no slice — its definition registry IS these M7 tuples — so the four
/// projections are what a harness sees of it: the pred_def emission above IS
/// a registration tuple, and the stable projections stay empty. Their
/// PRESENCE is what makes a later loss visible.
#[test]
fn the_dump_projects_the_predicate_registry() {
    let (text, deposited) = populated_dump();
    let start = quoted(&addr(&[1, 0, 1, 0, 1, 0, 1, 1]));
    let _ = &deposited;
    for entry in ["predicates.defs.audit", "predicates.defs.active"] {
        assert_entry(&text, entry, &format!("[{start}]"));
    }
    for entry in ["predicates.stable.audit", "predicates.stable.active"] {
        assert_entry(&text, entry, "[]");
    }
}

/// The determinism clause, stated over EQUAL WORLDS rather than one world: two
/// engines that ran the same history render byte-identically, though their M3
/// frontiers are separate `im::HashMap`s with separate hash seeds and iterate
/// in different orders. That is the whole reason the transcode sorts map
/// entries.
#[test]
fn two_engines_with_the_same_history_dump_byte_equal() {
    /// Three documents in one account, content in each, and every hint family
    /// in the first — enough distinct hashed keys that two coincidentally
    /// equal iteration orders are not the explanation.
    fn scripted() -> Engine {
        let engine = Engine::open(mem_cfg()).expect("in-memory open");
        let (acct, doc) = setup_doc(&engine);
        let (start, _) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])])
            .expect("insert succeeds");
        every_hint_family(&engine, &doc, &start);
        for byte in [b'r', b's', b't'] {
            let (d, _) = engine
                .namespace()
                .create_new_document(USER, &acct, None)
                .expect("the delegated owner may create a document");
            engine
                .vstream()
                .insert(OWNER, &d, vp(1, 1), vec![Val::new(vec![byte])])
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
fn a_recovered_world_dumps_byte_equal_to_the_live_fold() {
    let dir = tempdir().expect("tempdir");

    let dump_live;
    {
        let engine =
            Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let (_acct, doc) = setup_doc(&engine);

        // History batch A (below the checkpoint): content.
        let (start, _) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])])
            .expect("insert succeeds");

        // Checkpoint mid-history, so recovery is checkpoint + replay, not a
        // pure journal fold.
        engine.kernel().checkpoint().expect("checkpoint succeeds");

        // History batch B (the replay tail): every hint family, past the
        // checkpoint.
        every_hint_family(&engine, &doc, &start);

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
/// skip-serialized registry and hints gone, rebuilds both from the
/// authoritative links map, and only then replays the tail. The other
/// equivalence test checkpoints below the first link, so its rebuild runs over
/// an empty map and says nothing about this one.
#[test]
fn recovery_rebuilds_hints_from_a_checkpoint_that_already_holds_links() {
    let dir = tempdir().expect("tempdir");

    let dump_live;
    {
        let engine =
            Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let (_acct, doc) = setup_doc(&engine);
        let (start, _) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])])
            .expect("insert succeeds");
        every_hint_family(&engine, &doc, &start);

        // LOAD-BEARING: the checkpoint sits ABOVE every link, so the recovered
        // base is a world whose hints must be rebuilt rather than replayed.
        engine.kernel().checkpoint().expect("checkpoint succeeds");

        // A short replay tail above it, so recovery is genuinely base + fold.
        engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 3), vec![Val::new(vec![b'r'])])
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
    let (_acct, doc) = setup_doc(&engine);
    let (start, _) = engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])])
        .expect("insert succeeds");

    let past = engine.kernel().current_seq();
    every_hint_family(&engine, &doc, &start);

    let world = engine.world_at(past).expect("a committed boundary answers");
    engine.check_hints_of(&world).expect("a reconstructed world's hints match a rebuild");
    assert_ne!(
        engine.dump_of(&world),
        engine.world_dump(),
        "the reconstruction must be of the PAST, not of the head"
    );
}

/// A world the caller pinned itself — a snapshot rather than the engine's
/// own committed read — dumps deterministically and its hints are faithful,
/// with the genesis configuration supplied by the engine that produced it
/// (the harness shape: any world this engine made, rendered against the one
/// config it was sealed under).
#[test]
fn a_caller_pinned_world_dumps_deterministically() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let (_acct, doc) = setup_doc(&engine);
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'v'])])
        .expect("insert succeeds");

    let snap = engine.kernel().snapshot();
    let d1 = engine.dump_of(snap.world());
    let d2 = engine.dump_of(snap.world());
    assert_eq!(d1, d2);
    engine.check_hints_of(snap.world()).expect("hints are faithful");
}

/// The dump's vocabulary is part of its format, so it is pinned here rather
/// than left to whatever the assembler happens to call its fields: each
/// authoritative section is named for the store whose slice it renders, and
/// the banner names the version those keys belong to.
#[test]
fn the_dump_names_each_section_for_its_store() {
    let engine = Engine::open(mem_cfg()).expect("in-memory open");
    let text = engine.world_dump().into_string();

    assert!(text.starts_with("skep-world-dump v4\n"), "unexpected banner: {text:.32}");
    for section in [r#""namespace""#, r#""content""#, r#""arrangement""#, r#""links""#] {
        assert!(
            text.contains(section),
            "the authoritative section {section} must be named: {text:.200}"
        );
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
