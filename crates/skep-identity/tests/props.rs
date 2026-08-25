//! The invariants' Test clauses (I1–I9, AUTH-2.89–2.104): the I1 grammar
//! round-trip proptest over the WHOLE `Enrollment` domain, and the fold
//! proptests — determinism/composition (I2 AUTH-2.95), never-re-empties (I3
//! AUTH-2.97), retired-never-re-enter per `(account, fingerprint)` (I4
//! AUTH-2.98), genesis-at-most-once with the latch over all three homing
//! arms (I5 AUTH-2.100), claim first-wins (I6 AUTH-2.101), drafts
//! authenticate nowhere (I7 AUTH-2.102), non-credential deposits change
//! nothing (I8 AUTH-2.103), and the anchor flag's immutability per account
//! (I9 AUTH-2.104).

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use proptest::prelude::*;
use skep_address::Address;
use skep_identity::{
    encode_enroll, encode_retire, parse_enroll, parse_retire, Effect, Enrollment, Fingerprint,
    IdentityState, PublicKey, Verdict,
};

// ------------------------------------------------------------- I1 grammar

proptest! {
    /// I1 (AUTH-2.89) — `parse(encode(x)) == x` over `Enrollment`'s WHOLE
    /// domain: anchor flag included, labels via `Enrollment::new`, and the
    /// label generator (`.+`: any non-newline text, so labels ending in 0x20
    /// are generated, not dodged).
    #[test]
    fn i1_enroll_round_trip(
        entries in prop::collection::vec(
            (any::<[u8; 32]>(), any::<bool>(), proptest::option::of(".+")),
            1..8
        )
    ) {
        let mut enrollments: Vec<Enrollment> = Vec::new();
        for (raw, anchor, label) in entries {
            let key = PublicKey::Ed25519(raw);
            // One line per key: a record repeating a fingerprint is
            // DuplicateKey by grammar (AUTH-2.15), outside the record domain.
            if enrollments.iter().any(|e| e.key == key) {
                continue;
            }
            let e = Enrollment::new(key, anchor, label)
                .expect("generator labels contain no newline");
            enrollments.push(e);
        }
        let encoded = encode_enroll(&enrollments);
        let parsed = parse_enroll(&encoded);
        prop_assert!(matches!(&parsed, Ok(p) if *p == enrollments));
    }

    /// AUTH-2.17's round-trip on the retirement kind.
    #[test]
    fn i1_retire_round_trip(raws in prop::collection::vec(any::<[u8; 32]>(), 1..8)) {
        let mut fps: Vec<Fingerprint> = Vec::new();
        for raw in raws {
            let f = Fingerprint::of(&PublicKey::Ed25519(raw));
            if !fps.contains(&f) {
                fps.push(f);
            }
        }
        let parsed = parse_retire(&encode_retire(&fps));
        prop_assert!(matches!(&parsed, Ok(p) if *p == fps));
    }
}

// --------------------------------------------------------- stream fixture

/// One scripted deposit, pre-materialization. Kinds: 0 enroll, 1 retire,
/// 2 claim, 3 noise (an unrecognized type slot).
#[derive(Debug, Clone)]
struct Act {
    kind: u8,
    subject: usize,
    home: usize,
    keys: Vec<(u8, bool)>,
    fps: Vec<u8>,
}

const ACCOUNTS: [&[u32]; 5] = [CLM, ORG, NESTED, ACCT_A, ACCT_B];

/// Candidate homes: every account's doc 1 (own-space, registry-homed,
/// claimant-homed and stranger-homed arms all reachable — I5's three homing
/// arms) plus a second document (the home pin's refused residence).
fn homes() -> Vec<(Address, Address)> {
    vec![
        (doc1(CLM), addr(CLM)),
        (doc1(ORG), addr(ORG)),
        (doc1(NESTED), addr(NESTED)),
        (doc1(ACCT_A), addr(ACCT_A)),
        (doc1(ACCT_B), addr(ACCT_B)),
        (doc2(ACCT_A), addr(ACCT_A)),
    ]
}

fn act_strategy() -> impl Strategy<Value = Act> {
    (
        0..4u8,
        0..ACCOUNTS.len(),
        0..6usize,
        prop::collection::vec((0..6u8, any::<bool>()), 0..4),
        prop::collection::vec(0..6u8, 0..4),
    )
        .prop_map(|(kind, subject, home, keys, fps)| Act {
            kind,
            subject,
            home,
            keys,
            fps,
        })
}

struct Mat {
    dep: Dep,
    kind: u8,
    subject: Address,
    home_acct: Address,
}

fn materialize(fx: &mut Fixture, act: &Act) -> Mat {
    let subject_comps = ACCOUNTS[act.subject];
    let (home, home_acct) = homes()[act.home].clone();
    let dep = match act.kind {
        0 => fx.enroll_dep(&home, subject_comps, &enroll_payload(&act.keys)),
        1 => fx.retire_dep(&home, subject_comps, &retire_payload(&act.fps)),
        2 => fx.claim_dep(&home, subject_comps),
        _ => {
            let from = fx.mint(&home, &[b"noise"]);
            Dep {
                home: home.clone(),
                from,
                to: vec![unit(subject_comps)],
                // A content I-span of the commons doc: kind_of answers None.
                ty: vec![unit(&[1, 1, 0, 1, 0, 1, 0, 1, 1])],
            }
        }
    };
    Mat {
        dep,
        kind: act.kind,
        subject: addr(subject_comps),
        home_acct,
    }
}

// ------------------------------------------------------- the fold streams

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// I2/I3/I4/I5/I6/I8/I9 over random deposit streams, checked at every
    /// prefix, plus AUTH-2.57 (classify ≡ step's verdict) and the I2
    /// composition property `fold(s ++ t) == fold_from(fold(s), t)`.
    #[test]
    fn fold_invariants_hold_over_random_streams(
        acts in prop::collection::vec(act_strategy(), 1..40)
    ) {
        let mut fx = Fixture::new();
        let mats: Vec<Mat> = acts.iter().map(|a| materialize(&mut fx, a)).collect();
        let accounts: Vec<Address> = ACCOUNTS.iter().map(|c| addr(c)).collect();

        let mut st = IdentityState::genesis();
        let mut ever_nonempty: BTreeSet<Address> = BTreeSet::new();
        let mut retired_ever: BTreeSet<(Address, Fingerprint)> = BTreeSet::new();
        let mut first_flag: BTreeMap<(Address, Fingerprint), bool> = BTreeMap::new();
        let mut genesis_count: BTreeMap<Address, usize> = BTreeMap::new();
        let mut claims = 0usize;

        for mat in &mats {
            let pre_nonempty_subject = !st.key_set(&mat.subject).is_empty();
            let preview = fx.classify(&st, &mat.dep);
            let (next, verdict) = fx.step(&st, &mat.dep);

            // AUTH-2.57 — classify is exactly the verdict step reaches.
            prop_assert!(preview == verdict);
            // Only Honored moves the state (I8 for NotCredential, and every
            // inert verdict leaves the table untouched).
            if !matches!(verdict, Verdict::Honored(_)) {
                prop_assert!(next == st);
            }
            // I5 — the latch: once the subject's set has EVER been
            // non-empty, every enrollment homed outside its own space is
            // inert (registry-, claimant- and stranger-homed alike).
            if mat.kind == 0 && pre_nonempty_subject && mat.home_acct != mat.subject {
                prop_assert!(matches!(verdict, Verdict::Inert(_)));
            }

            match &verdict {
                Verdict::Honored(Effect::Genesis { account, keys }) => {
                    // I5 — at most one Honored(Genesis) per account, and
                    // never onto a set that was already non-empty.
                    prop_assert!(!pre_nonempty_subject);
                    *genesis_count.entry(account.clone()).or_insert(0) += 1;
                    prop_assert!(genesis_count[account] <= 1);
                    for k in keys {
                        first_flag
                            .entry((account.clone(), Fingerprint::of(&k.key)))
                            .or_insert(k.anchor);
                    }
                }
                Verdict::Honored(Effect::Enroll { account, added }) => {
                    for k in added {
                        first_flag
                            .entry((account.clone(), Fingerprint::of(&k.key)))
                            .or_insert(k.anchor);
                    }
                }
                Verdict::Honored(Effect::Retire { account, removed }) => {
                    for f in removed {
                        retired_ever.insert((account.clone(), *f));
                    }
                }
                Verdict::Honored(Effect::Claim { account: _ }) => {
                    // I6 — at most one Honored(Claim), only on an unclaimed
                    // board.
                    claims += 1;
                    prop_assert!(claims <= 1);
                    prop_assert!(st.claimant().is_none());
                }
                _ => {}
            }

            // I6 — `claimant` never changes once `Some`.
            if let Some(claimant) = st.claimant() {
                prop_assert!(next.claimant() == Some(claimant));
            }
            // I3 — `!S.is_empty()` is monotone over the stream.
            for acct in &ever_nonempty {
                prop_assert!(!next.key_set(acct).is_empty());
            }
            for acct in &accounts {
                if !next.key_set(acct).is_empty() {
                    ever_nonempty.insert(acct.clone());
                }
            }
            // I4 — per (account, fingerprint): retired ⇒ never enrolled
            // again in THAT account's set.
            for (acct, f) in &retired_ever {
                prop_assert!(!next.key_set(acct).contains(f));
            }
            // I9 — per (account, fingerprint): the flag anywhere (enrolled
            // or retired) equals the first-enrollment flag in that account.
            for ((acct, f), flag) in &first_flag {
                let s = next.key_set(acct);
                if let Some((_, e)) = s.enrolled().find(|(fp2, _)| *fp2 == f) {
                    prop_assert!(e.anchor == *flag);
                }
                if let Some((_, retired_flag)) = s.retired().find(|(fp2, _)| *fp2 == f) {
                    prop_assert!(retired_flag == *flag);
                }
            }

            st = next;
        }

        // I2 — `fold(s ++ t) == fold_from(fold(s), t)`, and re-folding the
        // whole stream reproduces the same table (determinism over a fixed
        // ctx and stream).
        let fold_over = |start: &IdentityState, slice: &[Mat]| -> IdentityState {
            let mut acc = start.clone();
            for mat in slice {
                acc = fx.step(&acc, &mat.dep).0;
            }
            acc
        };
        let whole = fold_over(&IdentityState::genesis(), &mats);
        prop_assert!(whole == st);
        let mid = mats.len() / 2;
        let head = fold_over(&IdentityState::genesis(), &mats[..mid]);
        let resumed = fold_over(&head, &mats[mid..]);
        prop_assert!(resumed == st);
    }

    /// I7 (AUTH-2.102) — `is_published == false ⇒ Inert(Unpublished)` for
    /// every credential shape, under a ctx stub deriving real (all-false)
    /// publication; non-credential deposits stay `NotCredential`.
    #[test]
    fn i7_drafts_authenticate_nowhere(
        acts in prop::collection::vec(act_strategy(), 1..20)
    ) {
        let mut fx = Fixture::new();
        fx.ctx.all_unpublished = true;
        let mats: Vec<Mat> = acts.iter().map(|a| materialize(&mut fx, a)).collect();
        let genesis = IdentityState::genesis();
        for mat in &mats {
            let (next, verdict) = fx.step(&genesis, &mat.dep);
            if mat.kind <= 2 {
                prop_assert!(token_of(&verdict).as_deref() == Some("unpublished"));
            } else {
                prop_assert!(matches!(verdict, Verdict::NotCredential));
            }
            prop_assert!(next == genesis);
        }
    }
}
