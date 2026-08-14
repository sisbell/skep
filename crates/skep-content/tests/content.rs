//! Integration tests for M4's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): what the one guard
//! admits and rejects (S0(b) no-overwrite), that the fold is pure and
//! insert-only, that identity is by address and never by value (S4), that
//! the journaled types survive a serde round trip (and M2's real
//! checkpoint-plus-replay recovery), and that each part of the interface
//! does its ordinary job on an ordinary input. The toy `World`/`Rec` pair is
//! the minimal engine assembly the composition contract prescribes:
//! `HasContent` read accessor, `From<ContentWrite>` record lift, `apply`
//! dispatching into `ContentStore::apply_write`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_content::{stage_write, write, ContentError, ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelCfg, TxnError, WorldState,
};
use skep_namespace::M3State;
use tempfile::tempdir;

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
struct World {
    content: ContentStore,
}

#[derive(Clone, Serialize, Deserialize)]
struct Rec(ContentWrite);

impl From<ContentWrite> for Rec {
    fn from(r: ContentWrite) -> Rec {
        Rec(r)
    }
}

impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

impl WorldState for World {
    type Record = Rec;
    fn apply(&self, r: &Rec) -> World {
        World {
            content: self.content.apply_write(&r.0),
        }
    }
}

// ---- helpers ----

fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

/// A content element address in M3's minted shape: doc `[1,0,1,0,1]`,
/// element field `[s_C = 1, ordinal]`.
fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

fn val(b: &[u8]) -> Val {
    Val::new(b)
}

fn genesis() -> World {
    World {
        content: ContentStore::default(),
    }
}

fn mem_kernel() -> Kernel<World> {
    let cfg = KernelCfg {
        // InMemory ignores the path entirely (M2 Lifecycle).
        journal_path: PathBuf::from("/nonexistent/skep-content-ignored"),
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        retain_checkpoints: 1,
    };
    Kernel::open(cfg, genesis()).expect("in-memory open")
}

fn cfg_fsync(dir: &Path) -> KernelCfg {
    KernelCfg {
        journal_path: dir.to_path_buf(),
        durability: Durability::Fsync {
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        retain_checkpoints: 1,
    }
}

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
fn rejected<T: std::fmt::Debug, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        other => panic!("expected TxnError::Rejected, got {other:?}"),
    }
}

// ---- §C stage_write: the pure step ----

#[test]
fn stage_write_admits_a_fresh_address_and_commits_nothing() {
    // §C: reads off a supplied slice, returns the record, commits nothing.
    let c = ContentStore::default();
    let a1 = ca(1);
    let rec = stage_write(&c, &a1, val(b"alpha")).expect("fresh address is admitted");
    // Read-public accessors report the staged pair (§A).
    assert_eq!(rec.addr(), a1.tumbler());
    assert_eq!(rec.val().as_bytes(), b"alpha");
    // Nothing committed: the supplied slice is untouched, so a second stage
    // of the same address against the SAME slice is admitted again — folding
    // between stages (working()) is the caller's obligation.
    assert!(!c.contains(a1.tumbler()));
    assert!(stage_write(&c, &a1, val(b"alpha")).is_ok());
}

#[test]
fn stage_write_rejects_an_occupied_address_with_already_present() {
    // S0(b) no-overwrite — M4's one genuine guard (§Invariants).
    let c = ContentStore::default();
    let a1 = ca(1);
    let c = c.apply_write(&stage_write(&c, &a1, val(b"first")).expect("fresh"));
    assert_eq!(
        stage_write(&c, &a1, val(b"second")).unwrap_err(),
        ContentError::AlreadyPresent(a1.tumbler().clone())
    );
    // The guard is per-address: a different fresh address is still admitted.
    assert!(stage_write(&c, &ca(2), val(b"second")).is_ok());
}

// ---- §A apply_write: the fold ----

#[test]
fn apply_write_is_a_pure_insert_only_fold() {
    // §A: pure — the receiver is untouched, a NEW slice is returned; S0(a)/S1
    // — the domain only grows.
    let c0 = ContentStore::default();
    assert!(c0.is_empty());
    assert_eq!(c0.len(), 0);
    let a1 = ca(1);
    let rec = stage_write(&c0, &a1, val(b"alpha")).expect("fresh");
    let c1 = c0.apply_write(&rec);
    // The prior slice still exists unchanged (persistent structural sharing —
    // this is what lets snapshots pin old Worlds).
    assert!(c0.is_empty());
    assert!(!c0.contains(a1.tumbler()));
    // The new slice holds the entry.
    assert!(c1.contains(a1.tumbler()));
    assert_eq!(c1.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"alpha"[..]));
    assert_eq!(c1.len(), 1);
    assert!(!c1.is_empty());
}

// ---- §B point queries ----

#[test]
fn point_queries_report_content_presence_only() {
    // §B: contains/value_at answer presence in dom(C) — nothing else. Absent
    // address ⇒ false/None, on the empty (Default) slice and next to a live
    // entry alike.
    let c = ContentStore::default();
    let a1 = ca(1);
    let a2 = ca(2);
    assert!(!c.contains(a1.tumbler()));
    assert!(c.value_at(a1.tumbler()).is_none());
    let c = c.apply_write(&stage_write(&c, &a1, val(b"alpha")).expect("fresh"));
    assert!(c.contains(a1.tumbler()));
    assert!(!c.contains(a2.tumbler()));
    assert!(c.value_at(a2.tumbler()).is_none());
}

#[test]
fn identity_is_by_address_never_by_value() {
    // S4: two equal byte-runs at two addresses are simply two entries — no
    // content-addressed collapse.
    let c = ContentStore::default();
    let a1 = ca(1);
    let a2 = ca(2);
    let c = c.apply_write(&stage_write(&c, &a1, val(b"same bytes")).expect("fresh"));
    let c = c.apply_write(&stage_write(&c, &a2, val(b"same bytes")).expect("fresh"));
    assert_eq!(c.len(), 2);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"same bytes"[..]));
    assert_eq!(c.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"same bytes"[..]));
}

// ---- §Types: Val and the record's Debug ----

#[test]
fn val_wraps_bytes_and_compares_by_content() {
    let from_slice = Val::new(b"payload".as_slice());
    let from_vec = Val::new(b"payload".to_vec());
    assert_eq!(from_slice.as_bytes(), b"payload");
    assert_eq!(from_slice.len(), 7);
    assert!(from_slice == from_vec);
    assert!(from_slice != Val::new(b"other".as_slice()));
    // A zero-length payload is a legal value.
    assert_eq!(Val::new(Vec::<u8>::new()).len(), 0);
}

#[test]
fn content_write_debug_renders_components_and_byte_length_only() {
    // §A: the manual Debug renders the address by its components (via
    // Tumbler::len/get) and the value by byte length — never the bytes.
    let a1 = ca(7);
    let rec = stage_write(&ContentStore::default(), &a1, val(b"abc")).expect("fresh");
    assert_eq!(
        format!("{rec:?}"),
        "ContentWrite { addr: [1, 0, 1, 0, 1, 0, 1, 7], val: 3 bytes }"
    );
}

// ---- serde: the journaled types ----

#[test]
fn journaled_types_survive_a_bincode_round_trip() {
    // §A/§Recovery: ContentWrite is the delta M2 journals; the slice is fully
    // serialized in checkpoints. bincode is M2's actual wire format.
    let a1 = ca(1);
    let a2 = ca(2);
    let rec = stage_write(&ContentStore::default(), &a1, val(b"payload")).expect("fresh");
    let bytes = bincode::serialize(&rec).expect("record serializes");
    let back: ContentWrite = bincode::deserialize(&bytes).expect("record deserializes");
    assert_eq!(back.addr(), rec.addr());
    assert!(back.val() == rec.val());
    // The replayed record folds to the same store effect (replay re-applies,
    // no re-derivation).
    let c = ContentStore::default().apply_write(&back);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"payload"[..]));

    // The slice round-trips whole (checkpoint form; rebuild_derived identity).
    let c = c.apply_write(&stage_write(&c, &a2, val(b"more")).expect("fresh"));
    let bytes = bincode::serialize(&c).expect("slice serializes");
    let back: ContentStore = bincode::deserialize(&bytes).expect("slice deserializes");
    assert_eq!(back.len(), 2);
    assert_eq!(back.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"payload"[..]));
    assert_eq!(back.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"more"[..]));
}

// ---- §C the standalone op over M2 ----

#[test]
fn standalone_write_commits_and_reads_back_through_a_snapshot() {
    let k = mem_kernel();
    let a1 = ca(1);
    let (stored, seq) = write(&k, &a1, val(b"alpha")).expect("fresh write commits");
    assert_eq!(stored, *a1.tumbler());
    assert_eq!(k.current_seq(), seq);
    // Bind the snapshot first; the &Val borrows THROUGH it (§B).
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert!(c.contains(a1.tumbler()));
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"alpha"[..]));
    assert_eq!(c.len(), 1);
}

#[test]
fn standalone_write_rejects_a_double_write_and_preserves_the_first_value() {
    // S0(b) through the composite: the second write is a clean typed
    // rejection (surfaced verbatim per M2), nothing committed, the stored
    // value untouched.
    let k = mem_kernel();
    let a1 = ca(1);
    write(&k, &a1, val(b"first")).expect("fresh write commits");
    let seq_before = k.current_seq();
    let err = rejected(write(&k, &a1, val(b"second")));
    assert_eq!(err, ContentError::AlreadyPresent(a1.tumbler().clone()));
    assert_eq!(k.current_seq(), seq_before);
    let s = k.snapshot();
    let c = s.world().content();
    assert_eq!(c.len(), 1);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"first"[..]));
}

#[test]
fn stage_write_composes_into_one_transaction_off_the_working_slice() {
    // The M5-shape composite (§Dependencies & seams): m records staged via
    // stage_write against stg.working().content() in ONE transact, committed
    // under one marker; the working slice reflects each push, so an
    // intra-composite double-stage is rejected.
    let k = mem_kernel();
    let d = a(&[1, 0, 1, 0, 1]);
    let a1 = ca(1);
    let a2 = ca(2);
    let (_, seq) = k
        .transact(&[M3State::content_lock_key(&d)], |stg| {
            let r1 = stage_write(stg.working().content(), &a1, val(b"one"))?;
            stg.push(r1.into());
            // working() reflects the push: re-staging a1 here is rejected.
            assert!(matches!(
                stage_write(stg.working().content(), &a1, val(b"dup")),
                Err(ContentError::AlreadyPresent(t)) if t == *a1.tumbler()
            ));
            let r2 = stage_write(stg.working().content(), &a2, val(b"two"))?;
            stg.push(r2.into());
            // Pins the closure's error parameter: `?` on stage_write only
            // constrains `E: From<ContentError>`, which infers nothing.
            Ok::<(), ContentError>(())
        })
        .expect("composite commits");
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert_eq!(c.len(), 2);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"one"[..]));
    assert_eq!(c.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"two"[..]));
}

#[cfg(not(feature = "content-addr-guard"))]
#[test]
#[should_panic(expected = "content address ⇒ zeros = 3")]
fn standalone_write_panics_at_key_derivation_on_a_non_content_address() {
    // §C: in the base build the document_of .expect IS the trusted-address
    // contract — a zeros < 2 input is an internal invariant violation, never
    // a domain rejection.
    let k = mem_kernel();
    let account = a(&[1, 0, 1]);
    let _ = write(&k, &account, val(b"x"));
}

// ---- M2-driven recovery: checkpoint load + tail replay ----

#[test]
fn content_survives_durable_recovery_by_checkpoint_and_replay() {
    // §Recovery: M4 owns no recovery machinery — M2's open loads the latest
    // checkpoint (deserializing the slice) and replays the tail by folding
    // ContentWrite records through apply → apply_write. a1 rides the
    // checkpoint path, a2 the replay path.
    let dir = tempdir().expect("tempdir");
    let a1 = ca(1);
    let a2 = ca(2);
    {
        let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
        write(&k, &a1, val(b"alpha")).expect("first write");
        k.checkpoint().expect("checkpoint");
        write(&k, &a2, val(b"beta")).expect("second write");
    }
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    let s = k.snapshot();
    let c = s.world().content();
    assert_eq!(c.len(), 2);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"alpha"[..]));
    assert_eq!(c.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"beta"[..]));
    // The recovered dom(C) still feeds the S0(b) guard.
    drop(s);
    assert_eq!(
        rejected(write(&k, &a1, val(b"again"))),
        ContentError::AlreadyPresent(a1.tumbler().clone())
    );
}

// ---- Open build decision #4: the content-addr-guard feature ----

#[cfg(feature = "content-addr-guard")]
mod guard {
    use super::*;

    #[test]
    fn guard_admits_content_addresses_and_already_present_still_guards_occupancy() {
        // The routing check admits a proper content-subspace element address;
        // the overwrite check remains reachable behind it (§C check order).
        let c = ContentStore::default();
        let a1 = ca(1);
        let r = stage_write(&c, &a1, val(b"x")).expect("guard admits a content address");
        let c = c.apply_write(&r);
        assert_eq!(
            stage_write(&c, &a1, val(b"y")).unwrap_err(),
            ContentError::AlreadyPresent(a1.tumbler().clone())
        );
    }

    // The debug-assert sub-choice fires only in debug builds.
    #[cfg(debug_assertions)]
    mod panics {
        use super::*;

        #[test]
        #[should_panic(expected = "content-addr-guard: stage_write")]
        fn guard_rejects_a_link_subspace_address() {
            let link_elem = a(&[1, 0, 1, 0, 1, 0, 2, 1]); // subspace s_L = 2
            let _ = stage_write(&ContentStore::default(), &link_elem, val(b"x"));
        }

        #[test]
        #[should_panic(expected = "content-addr-guard: stage_write")]
        fn guard_rejects_a_non_element_address() {
            let doc = a(&[1, 0, 1, 0, 1]);
            let _ = stage_write(&ContentStore::default(), &doc, val(b"x"));
        }

        #[test]
        #[should_panic(expected = "content-addr-guard: write")]
        fn guard_runs_before_lock_key_derivation_in_write() {
            // §C hoist: a zeros = 1 input must be rejected by the routing
            // guard on its own terms — the expected message proves it fired
            // BEFORE the document_of .expect (whose message differs).
            let k = mem_kernel();
            let account = a(&[1, 0, 1]);
            let _ = write(&k, &account, val(b"x"));
        }
    }
}
