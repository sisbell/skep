use super::*;

fn fsync_mode(burned_seq: BurnedSeqPolicy) -> Durability {
    Durability::Fsync {
        journal_path: PathBuf::from("/tmp/skep-kernel-config-test"),
        retain_checkpoints: 1,
        burned_seq,
        cut_damaged_tail: false,
    }
}

#[test]
fn the_burned_seq_policy_is_a_property_of_the_durability_mode() {
    assert_eq!(
        fsync_mode(BurnedSeqPolicy::Rollback).burned_seq_policy(),
        BurnedSeqPolicy::Rollback
    );
    assert_eq!(
        fsync_mode(BurnedSeqPolicy::TolerateGap).burned_seq_policy(),
        BurnedSeqPolicy::TolerateGap
    );
    // The in-memory mode carries no policy of its own and answers with
    // the default, which keeps its order gap-free.
    assert_eq!(
        Durability::InMemory.burned_seq_policy(),
        BurnedSeqPolicy::default()
    );
}

#[test]
fn the_retention_rule_binds_the_journal_and_nothing_else() {
    // `N ≥ 1` is a rule about a journal's fallback chain, so it is
    // checked where a journal is configured and is vacuous where none is.
    let bad = KernelConfig {
        durability: Durability::Fsync {
            journal_path: PathBuf::from("/tmp/skep-kernel-config-test"),
            retain_checkpoints: 0,
            burned_seq: BurnedSeqPolicy::Rollback,
            cut_damaged_tail: false,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Os,
    };
    assert_eq!(
        bad.validate().unwrap_err(),
        "retain_checkpoints must be >= 1"
    );
    let in_memory = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Os,
    };
    assert!(in_memory.validate().is_ok());
}

/// An empty `journal_path` names no directory, and is refused at `open`
/// before the lock is taken or a file read — where, unrefused, every name the
/// kernel joins to it would resolve against whatever directory the process
/// runs in. It is the journal's first rule, so it speaks ahead of the
/// retention rule beside it; a path that names anything passes it, a
/// relative one among them, which `open` resolves once.
#[test]
fn an_empty_journal_path_is_refused_ahead_of_every_other_rule() {
    let with = |journal_path: &str, retain_checkpoints| KernelConfig {
        durability: Durability::Fsync {
            journal_path: PathBuf::from(journal_path),
            retain_checkpoints,
            burned_seq: BurnedSeqPolicy::Rollback,
            cut_damaged_tail: false,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Os,
    };
    let empty = "journal_path must name a directory; an empty path names none";
    assert_eq!(with("", 1).validate().unwrap_err(), empty);
    assert_eq!(with("", 0).validate().unwrap_err(), empty, "the path's rule speaks first");
    for named in [".", "board", "/tmp/skep-kernel-config-test"] {
        assert!(with(named, 1).validate().is_ok(), "{named:?} names a directory");
    }
}

#[test]
fn both_salt_sources_are_modes_this_kernel_offers() {
    // The salt knob carries no rule: which source a deployment may use is
    // the caller's discipline (a daemon is `Os`), and a configuration
    // cannot check it. Both validate, in either durability mode.
    for salt in [SaltSource::Os, SaltSource::Seeded(0), SaltSource::Seeded(u64::MAX)] {
        for durability in [Durability::InMemory, fsync_mode(BurnedSeqPolicy::Rollback)] {
            let cfg = KernelConfig {
                durability,
                checkpoint: CheckpointPolicy::Manual,
                salt,
            };
            assert!(cfg.validate().is_ok(), "{salt:?} is a mode this offers");
        }
    }
}

#[test]
fn the_seeded_salt_is_a_pure_function_of_the_seed_and_the_transaction() {
    // The formula, spelled out by hand beside the source: SHA-256 over
    // the seed's eight little-endian bytes then the transaction's — so a
    // replayed op sequence under one seed writes one history, and the
    // golden fixture's markers carry exactly these bytes.
    let by_hand = |seed: u64, txn: u64| -> [u8; 32] {
        let mut preimage = Vec::with_capacity(16);
        preimage.extend_from_slice(&seed.to_le_bytes());
        preimage.extend_from_slice(&txn.to_le_bytes());
        Sha256::digest(&preimage).into()
    };
    for (seed, txn) in [(0, 1), (7, 1), (7, 2), (u64::MAX, u64::MAX)] {
        assert_eq!(SaltSource::Seeded(seed).draw(txn).unwrap(), by_hand(seed, txn));
    }
    // Deterministic across draws, distinct across transactions and across
    // seeds: two journals under two seeds salt every transaction differently.
    let seeded = SaltSource::Seeded(7);
    assert_eq!(seeded.draw(1).unwrap(), seeded.draw(1).unwrap());
    assert_ne!(seeded.draw(1).unwrap(), seeded.draw(2).unwrap());
    assert_ne!(seeded.draw(1).unwrap(), SaltSource::Seeded(8).draw(1).unwrap());
    assert_ne!(seeded.draw(1).unwrap(), [0u8; 32], "a salt is never thirty-two zero bytes");
}

#[test]
fn the_os_source_draws_fresh_entropy_on_every_call() {
    // Two draws for ONE transaction differ: the OS source is a function
    // of nothing the caller supplies, which is what makes a chain value
    // under it confirm no guess. (Equal draws would be a 2^-256 event.)
    let first = SaltSource::Os.draw(1).expect("OS entropy");
    let second = SaltSource::Os.draw(1).expect("OS entropy");
    assert_ne!(first, second, "the OS source repeated a salt");
    assert_ne!(first, [0u8; 32]);
    assert_ne!(first, SaltSource::Seeded(0).draw(1).unwrap(), "not the seeded stream");
}

#[test]
fn a_zero_auto_trigger_threshold_is_refused_in_either_durability_mode() {
    // "Checkpoint after every 0 commits" has no meaning, and coercing it
    // would read as the most expensive mode this kernel has — a whole
    // checkpoint on the committing thread at every commit, whose failure
    // never reaches `transact`'s caller and is kept only as a record.
    // `Manual` is what asks for no auto-trigger, so the mistake has an
    // answer and gets named rather than performed.
    let with = |checkpoint| KernelConfig {
        durability: Durability::InMemory,
        checkpoint,
        salt: SaltSource::Os,
    };
    assert_eq!(
        with(CheckpointPolicy::EveryN(0)).validate().unwrap_err(),
        "CheckpointPolicy::EveryN requires n >= 1; Manual disables the auto-trigger"
    );
    assert_eq!(
        with(CheckpointPolicy::JournalBytes(0))
            .validate()
            .unwrap_err(),
        "CheckpointPolicy::JournalBytes requires n >= 1; Manual disables the auto-trigger"
    );
    // The trigger has no journal to ride on, so the rule binds both modes
    // — and it is the trigger's rule that speaks, not the retention one.
    let journaled = KernelConfig {
        durability: fsync_mode(BurnedSeqPolicy::Rollback),
        checkpoint: CheckpointPolicy::EveryN(0),
        salt: SaltSource::Os,
    };
    assert_eq!(
        journaled.validate().unwrap_err(),
        "CheckpointPolicy::EveryN requires n >= 1; Manual disables the auto-trigger"
    );

    // Everything at or above the floor validates — including a zero
    // `Interval`, which is an always-elapsed window rather than a
    // thresholdless one, and is what `interval_is_evaluated_on_commit…`
    // pins.
    for policy in [
        CheckpointPolicy::EveryN(1),
        CheckpointPolicy::JournalBytes(1),
        CheckpointPolicy::Interval(Duration::ZERO),
        CheckpointPolicy::Manual,
    ] {
        assert!(
            with(policy.clone()).validate().is_ok(),
            "{policy:?} is a mode this offers"
        );
    }
}

/// The two arms that hold policies of their own are held to the same
/// rules, arm by arm: a zero threshold inside either is refused with the
/// inner arm's own sentence, and `Deferred` is the outermost arm alone —
/// inside a composite, or inside itself, it is refused by name. The
/// shapes the daemon opens under validate: a deferred composite of a
/// commit count and a byte bound, and each half alone under `Deferred`.
#[test]
fn the_composite_and_the_deferred_arm_hold_their_halves_to_the_rules() {
    let either = |a: CheckpointPolicy, b: CheckpointPolicy| {
        CheckpointPolicy::EitherOf(Box::new(a), Box::new(b))
    };
    let deferred = |inner: CheckpointPolicy| CheckpointPolicy::Deferred(Box::new(inner));
    let with = |checkpoint| KernelConfig {
        durability: Durability::InMemory,
        checkpoint,
        salt: SaltSource::Os,
    };
    for policy in [
        deferred(either(CheckpointPolicy::EveryN(1024), CheckpointPolicy::JournalBytes(1))),
        either(CheckpointPolicy::EveryN(1), CheckpointPolicy::JournalBytes(1)),
        deferred(CheckpointPolicy::EveryN(1)),
        deferred(CheckpointPolicy::JournalBytes(1)),
        deferred(CheckpointPolicy::Interval(Duration::ZERO)),
        deferred(CheckpointPolicy::Manual),
        either(CheckpointPolicy::Interval(Duration::ZERO), CheckpointPolicy::Manual),
    ] {
        assert!(with(policy.clone()).validate().is_ok(), "{policy:?} is a mode this offers");
    }
    assert_eq!(
        with(either(CheckpointPolicy::EveryN(0), CheckpointPolicy::JournalBytes(1)))
            .validate()
            .unwrap_err(),
        "CheckpointPolicy::EveryN requires n >= 1; Manual disables the auto-trigger"
    );
    assert_eq!(
        with(either(CheckpointPolicy::EveryN(1), CheckpointPolicy::JournalBytes(0)))
            .validate()
            .unwrap_err(),
        "CheckpointPolicy::JournalBytes requires n >= 1; Manual disables the auto-trigger"
    );
    assert_eq!(
        with(deferred(CheckpointPolicy::JournalBytes(0))).validate().unwrap_err(),
        "CheckpointPolicy::JournalBytes requires n >= 1; Manual disables the auto-trigger"
    );
    let nested = "CheckpointPolicy::Deferred is the outermost arm alone; it wraps the others";
    assert_eq!(
        with(deferred(deferred(CheckpointPolicy::EveryN(1)))).validate().unwrap_err(),
        nested
    );
    assert_eq!(
        with(either(deferred(CheckpointPolicy::EveryN(1)), CheckpointPolicy::Manual))
            .validate()
            .unwrap_err(),
        nested
    );
    assert_eq!(
        with(deferred(either(CheckpointPolicy::Manual, deferred(CheckpointPolicy::Manual))))
            .validate()
            .unwrap_err(),
        nested
    );
}

/// The deferral is read off the outermost arm alone, and the byte bound
/// moves wherever the arms nest it — in a bare `JournalBytes`, inside a
/// composite, inside a deferred composite — while a policy holding none
/// answers that nothing moved and stays as it was.
#[test]
fn the_byte_bound_moves_in_place_and_the_deferral_is_the_outermost_arms() {
    let bound = NonZeroU64::new(7).unwrap();
    let mut bare = CheckpointPolicy::JournalBytes(1);
    assert!(bare.set_bytes(bound));
    assert_eq!(bare, CheckpointPolicy::JournalBytes(7));
    assert!(!bare.deferred());

    let mut composite = CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EitherOf(
        Box::new(CheckpointPolicy::EveryN(1024)),
        Box::new(CheckpointPolicy::JournalBytes(1)),
    )));
    assert!(composite.deferred());
    assert!(composite.set_bytes(bound));
    assert_eq!(
        composite,
        CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EitherOf(
            Box::new(CheckpointPolicy::EveryN(1024)),
            Box::new(CheckpointPolicy::JournalBytes(7)),
        )))
    );

    for mut unmoved in [
        CheckpointPolicy::EveryN(3),
        CheckpointPolicy::Interval(Duration::ZERO),
        CheckpointPolicy::Manual,
        CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EveryN(3))),
    ] {
        let before = unmoved.clone();
        assert!(!unmoved.set_bytes(bound), "{before:?} holds no byte bound");
        assert_eq!(unmoved, before, "…and is left as it was");
    }
}

/// The commit bound moves wherever the arms nest it, as the byte bound does
/// — in a bare `EveryN`, inside a deferred composite, leaving the byte half
/// beside it as it was — while a policy holding none answers that nothing
/// moved and stays as it was.
#[test]
fn the_commit_bound_moves_in_place_as_the_byte_bound_does() {
    let count = NonZeroU64::new(9).unwrap();
    let mut bare = CheckpointPolicy::EveryN(1);
    assert!(bare.set_commits(count));
    assert_eq!(bare, CheckpointPolicy::EveryN(9));

    let mut composite = CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EitherOf(
        Box::new(CheckpointPolicy::EveryN(1024)),
        Box::new(CheckpointPolicy::JournalBytes(1)),
    )));
    assert!(composite.set_commits(count));
    assert_eq!(
        composite,
        CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EitherOf(
            Box::new(CheckpointPolicy::EveryN(9)),
            Box::new(CheckpointPolicy::JournalBytes(1)),
        )))
    );

    for mut unmoved in [
        CheckpointPolicy::JournalBytes(3),
        CheckpointPolicy::Interval(Duration::ZERO),
        CheckpointPolicy::Manual,
        CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::JournalBytes(3))),
    ] {
        let before = unmoved.clone();
        assert!(!unmoved.set_commits(count), "{before:?} holds no commit bound");
        assert_eq!(unmoved, before, "…and is left as it was");
    }
}
