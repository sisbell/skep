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
        prop_assert_eq!(parsed, Ok(enrollments));
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
        prop_assert_eq!(parsed, Ok(fps));
    }
}

// --------------------------------------------------------- stream fixture

/// The four acts a scripted stream can carry — the strategy's `0..4` draw
/// given a name, so no property reads a numeric code and no added kind can
/// fall through a wildcard into `Noise`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActKind {
    Enroll,
    Retire,
    Claim,
    Noise,
}

impl ActKind {
    /// The strategy's draw, mapped in ONE place.
    fn from_draw(n: u8) -> ActKind {
        match n {
            0 => ActKind::Enroll,
            1 => ActKind::Retire,
            2 => ActKind::Claim,
            _ => ActKind::Noise,
        }
    }

    /// ⇔ the act is one of the three shapes `kind_of` recognizes — what I7
    /// asks of an act before it demands `unpublished` (AUTH-2.102); `Noise`
    /// is `NotCredential` whatever the board. Matched exhaustively, so an
    /// added kind states its own answer here rather than inheriting one.
    fn is_credential(self) -> bool {
        match self {
            ActKind::Enroll | ActKind::Retire | ActKind::Claim => true,
            ActKind::Noise => false,
        }
    }
}

/// One scripted deposit, pre-materialization.
#[derive(Debug, Clone)]
struct Act {
    kind: ActKind,
    subject: usize,
    home: usize,
    keys: Vec<(u8, bool)>,
    fps: Vec<u8>,
}

const ACCOUNTS: [&[u32]; 5] = [CLAIMANT, ORG, NESTED, ACCT_A, ACCT_B];

/// Candidate homes: every account's doc 1 (own-space, registry-homed,
/// claimant-homed and stranger-homed arms all reachable — I5's three homing
/// arms) plus a second document (the home pin's refused residence).
fn homes() -> Vec<(Address, Address)> {
    vec![
        (doc1(CLAIMANT), addr(CLAIMANT)),
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
            kind: ActKind::from_draw(kind),
            subject,
            home,
            keys,
            fps,
        })
}

/// One case of the property: a scripted [`Act`] materialized into the
/// deposit the fold sees, beside the two addresses the invariants reason
/// over.
struct Case {
    dep: Dep,
    kind: ActKind,
    subject: Address,
    home_account: Address,
}

fn materialize(fx: &mut Fixture, act: &Act) -> Case {
    let subject_comps = ACCOUNTS[act.subject];
    let (home, home_account) = homes()[act.home].clone();
    let dep = match act.kind {
        ActKind::Enroll => fx.enroll_dep(&home, subject_comps, &enroll_payload(&act.keys)),
        ActKind::Retire => fx.retire_dep(&home, subject_comps, &retire_payload(&act.fps)),
        ActKind::Claim => fx.claim_dep(&home, subject_comps),
        ActKind::Noise => {
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
    Case {
        dep,
        kind: act.kind,
        subject: addr(subject_comps),
        home_account,
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
        let cases: Vec<Case> = acts.iter().map(|a| materialize(&mut fx, a)).collect();
        let accounts: Vec<Address> = ACCOUNTS.iter().map(|c| addr(c)).collect();

        let mut st = IdentityState::genesis();
        let mut ever_nonempty: BTreeSet<Address> = BTreeSet::new();
        let mut ever_retired: BTreeSet<(Address, Fingerprint)> = BTreeSet::new();
        let mut first_flag: BTreeMap<(Address, Fingerprint), bool> = BTreeMap::new();
        let mut genesis_count: BTreeMap<Address, usize> = BTreeMap::new();
        let mut claims = 0usize;

        for case in &cases {
            let pre_nonempty_subject = !st.key_set(&case.subject).is_empty();
            let preview = fx.classify(&st, &case.dep);
            let (next, verdict) = fx.step(&st, &case.dep);

            // AUTH-2.57 — classify is exactly the verdict step reaches.
            prop_assert_eq!(&preview, &verdict);
            // Only Honored moves the state (I8 for NotCredential, and every
            // inert verdict leaves the table untouched).
            if !matches!(verdict, Verdict::Honored(_)) {
                prop_assert_eq!(&next, &st);
            }
            // I5 — the latch: once the subject's set has EVER been
            // non-empty, every enrollment homed outside its own space is
            // inert (registry-, claimant- and stranger-homed alike).
            if case.kind == ActKind::Enroll
                && pre_nonempty_subject
                && case.home_account != case.subject
            {
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
                        ever_retired.insert((account.clone(), *f));
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
                prop_assert_eq!(next.claimant(), Some(claimant));
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
            for (acct, f) in &ever_retired {
                prop_assert!(!next.key_set(acct).contains(f));
            }
            // I9 — per (account, fingerprint): the flag anywhere (enrolled
            // or retired) equals the first-enrollment flag in that account.
            for ((acct, f), flag) in &first_flag {
                let s = next.key_set(acct);
                if let Some((_, enrolled)) =
                    s.enrolled().find(|(enrolled_fp, _)| *enrolled_fp == f)
                {
                    prop_assert_eq!(enrolled.anchor, *flag);
                }
                if let Some((_, retired_flag)) =
                    s.retired().find(|(retired_fp, _)| *retired_fp == f)
                {
                    prop_assert_eq!(retired_flag, *flag);
                }
            }

            st = next;
        }

        // I2 — `fold(s ++ t) == fold_from(fold(s), t)`, and re-folding the
        // whole stream reproduces the same table (determinism over a fixed
        // ctx and stream).
        let fold_over = |start: &IdentityState, slice: &[Case]| -> IdentityState {
            let mut acc = start.clone();
            for case in slice {
                acc = fx.step(&acc, &case.dep).0;
            }
            acc
        };
        let whole = fold_over(&IdentityState::genesis(), &cases);
        prop_assert_eq!(&whole, &st);
        let mid = cases.len() / 2;
        let head = fold_over(&IdentityState::genesis(), &cases[..mid]);
        let resumed = fold_over(&head, &cases[mid..]);
        prop_assert_eq!(&resumed, &st);
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
        let cases: Vec<Case> = acts.iter().map(|a| materialize(&mut fx, a)).collect();
        let genesis_state = IdentityState::genesis();
        for case in &cases {
            let (next, verdict) = fx.step(&genesis_state, &case.dep);
            if case.kind.is_credential() {
                let token = token_of(&verdict);
                prop_assert_eq!(token.as_deref(), Some("unpublished"));
            } else {
                prop_assert!(matches!(verdict, Verdict::NotCredential));
            }
            prop_assert_eq!(&next, &genesis_state);
        }
    }
}
