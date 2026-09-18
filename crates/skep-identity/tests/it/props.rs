//! The invariants' Test clauses (I1–I9, AUTH-2.89–2.104): the I1 grammar
//! round-trip proptest over the WHOLE `Enrollment` domain, and the fold
//! proptests — determinism/composition (I2 AUTH-2.95), never-re-empties (I3
//! AUTH-2.97), retired-never-re-enter per `(account, fingerprint)` (I4
//! AUTH-2.98), genesis-at-most-once with the latch over all three homing
//! arms (I5 AUTH-2.100), claim first-wins (I6 AUTH-2.101), drafts
//! authenticate nowhere (I7 AUTH-2.102), non-credential deposits change
//! nothing (I8 AUTH-2.103), and the anchor flag's immutability per account
//! (I9 AUTH-2.104); beside them, AUTH-2.127's home pin and `IdentityState`'s
//! keyed rows as laws over the same streams.

use crate::common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use proptest::prelude::*;
use skep_address::Address;
use skep_identity::{
    encode_enroll, encode_retire, parse_enroll, parse_retire, Effect, Enrollment, Fingerprint,
    IdentityState, PublicKey, Verdict,
};

// ------------------------------------------------------------- I1 grammar

/// A NON-EMPTY, DUPLICATE-FREE `Vec<Enrollment>` — the record domain per entry:
/// `anchor` flag included, labels via `Enrollment::new`, and the label
/// generator `.+` (any non-newline text, so labels ending in 0x20 or carrying
/// `"`, `\`, a tab or a control char are generated, not dodged — AUTH-2.89
/// forbids narrowing to dodge them).
fn enroll_entries() -> impl Strategy<Value = Vec<Enrollment>> {
    prop::collection::vec((any::<[u8; 32]>(), any::<bool>(), prop::option::of(".+")), 1..8)
        .prop_map(|raws| {
            let mut out: Vec<Enrollment> = Vec::new();
            for (raw, anchor, label) in raws {
                let key = PublicKey::Ed25519(raw);
                // One entry per key: a record repeating a fingerprint is
                // DuplicateKey (AUTH-2.15), outside the record domain.
                if out.iter().any(|e| e.key == key) {
                    continue;
                }
                out.push(Enrollment::new(key, anchor, label).expect("generator labels have no newline"));
            }
            out
        })
        .prop_filter("at least one entry", |v| !v.is_empty())
}

/// A NON-EMPTY, DUPLICATE-FREE `Vec<Fingerprint>` — the retirement record domain.
fn retire_fps() -> impl Strategy<Value = Vec<Fingerprint>> {
    prop::collection::vec(any::<[u8; 32]>(), 1..8)
        .prop_map(|raws| {
            let mut out: Vec<Fingerprint> = Vec::new();
            for raw in raws {
                let f = Fingerprint::of(&PublicKey::Ed25519(raw));
                if !out.contains(&f) {
                    out.push(f);
                }
            }
            out
        })
        .prop_filter("at least one fingerprint", |v| !v.is_empty())
}

/// Splice a canonical `sig` member (canonically LAST) into a canonical record
/// body's closing brace. The `sig` charset is printable ASCII minus `"` and
/// `\`, so it needs no escaping and the spliced body is canonical.
fn with_canonical_sig(base: &str, sig: &str) -> String {
    format!("{},\"sig\":\"{sig}\"}}", &base[..base.len() - 1])
}

proptest! {
    /// I1 (AUTH-2.89) DIRECTION 1 — `parse(encode(x)) == x` over `Enrollment`'s
    /// WHOLE domain, both kinds.
    #[test]
    fn i1_parse_encode_round_trip(entries in enroll_entries(), fps in retire_fps()) {
        prop_assert_eq!(parse_enroll(encode_enroll(&entries).as_bytes()), Ok(entries));
        prop_assert_eq!(parse_retire(encode_retire(&fps).as_bytes()), Ok(fps));
    }

    /// I1 (AUTH-2.89) DIRECTION 2 (RES-105) — `encode(parse(y)) == y` over THE
    /// RECORD VALUE (AUTH-2.130), the generator carrying bodies WITH and
    /// WITHOUT a `sig` member: a no-sig admitted body re-encodes to itself, and
    /// a sig-bearing admitted body is ADMITTED (the admission ranges over the
    /// value, `sig` included) and answers the same entries, `encode_*` emitting
    /// the sig-STRIPPED body (AUTH-2.13, AUTH-2.94, AUTH-2.130).
    #[test]
    fn i1_encode_parse_bijection_over_the_record_value(
        entries in enroll_entries(),
        fps in retire_fps(),
        enroll_sig in prop::option::of("[ -~&&[^\"\\\\]]{0,40}"),
        retire_sig in prop::option::of("[ -~&&[^\"\\\\]]{0,40}"),
    ) {
        // Enrolment: the no-sig body re-encodes to itself.
        let base = encode_enroll(&entries);
        prop_assert_eq!(&encode_enroll(&parse_enroll(base.as_bytes()).unwrap()), &base);
        if let Some(sig) = enroll_sig {
            let with_sig = with_canonical_sig(&base, &sig);
            let admitted = parse_enroll(with_sig.as_bytes());
            prop_assert_eq!(&admitted, &Ok(entries.clone()), "the sig-bearing body is admitted, sig skipped");
            prop_assert_eq!(encode_enroll(&admitted.unwrap()), base.clone(), "encode emits no sig");
        }
        // Retirement: the same, both ways.
        let base = encode_retire(&fps);
        prop_assert_eq!(&encode_retire(&parse_retire(base.as_bytes()).unwrap()), &base);
        if let Some(sig) = retire_sig {
            let with_sig = with_canonical_sig(&base, &sig);
            let admitted = parse_retire(with_sig.as_bytes());
            prop_assert_eq!(&admitted, &Ok(fps.clone()), "the sig-bearing body is admitted, sig skipped");
            prop_assert_eq!(encode_retire(&admitted.unwrap()), base.clone(), "encode emits no sig");
        }
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
    subject_index: usize,
    home_index: usize,
    enroll_entries: Vec<(u8, bool)>,
    retire_indices: Vec<u8>,
}

const ACCOUNTS: [&[u32]; 5] = [CLAIMANT, ORG, NESTED, ACCT_A, ACCT_B];

/// Candidate homes, each beside its home account and that account's doc 1 —
/// a literal table, so the oracle the properties compare against is not the
/// resolution the fold computes: every account's doc 1 (own-space,
/// registry-homed, claimant-homed and stranger-homed arms all reachable —
/// I5's three homing arms) plus the home pin's two refused residences, a
/// second document and doc 1's own version member.
fn homes() -> Vec<(Address, Address, Address)> {
    vec![
        (doc1(CLAIMANT), addr(CLAIMANT), doc1(CLAIMANT)),
        (doc1(ORG), addr(ORG), doc1(ORG)),
        (doc1(NESTED), addr(NESTED), doc1(NESTED)),
        (doc1(ACCT_A), addr(ACCT_A), doc1(ACCT_A)),
        (doc1(ACCT_B), addr(ACCT_B), doc1(ACCT_B)),
        (doc2(ACCT_A), addr(ACCT_A), doc1(ACCT_A)),
        (first_version_of(&doc1(ACCT_A)), addr(ACCT_A), doc1(ACCT_A)),
    ]
}

fn act_strategy() -> impl Strategy<Value = Act> {
    (
        0..4u8,
        0..ACCOUNTS.len(),
        0..homes().len(),
        prop::collection::vec((0..6u8, any::<bool>()), 0..4),
        prop::collection::vec(0..6u8, 0..4),
    )
        .prop_map(|(kind, subject_index, home_index, enroll_entries, retire_indices)| Act {
            kind: ActKind::from_draw(kind),
            subject_index,
            home_index,
            enroll_entries,
            retire_indices,
        })
}

/// One case of the property: a scripted [`Act`] materialized into the
/// deposit the fold sees, beside the addresses the invariants reason over —
/// the subject, the home's account, and that account's doc 1.
struct Case {
    dep: Dep,
    kind: ActKind,
    subject: Address,
    home_account: Address,
    home_doc_one: Address,
}

fn materialize(fx: &mut Fixture, act: &Act) -> Case {
    let subject_comps = ACCOUNTS[act.subject_index];
    let (home, home_account, home_doc_one) = homes()[act.home_index].clone();
    let dep = match act.kind {
        ActKind::Enroll => {
            fx.enroll_dep(&home, subject_comps, &enroll_payload(&act.enroll_entries))
        }
        ActKind::Retire => {
            fx.retire_dep(&home, subject_comps, &retire_payload(&act.retire_indices))
        }
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
        home_doc_one,
    }
}

// ------------------------------------------------------- the fold streams

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// I2/I3/I4/I5/I6/I8/I9 over random deposit streams, checked at every
    /// prefix, plus AUTH-2.57 (classify ≡ step's verdict), AUTH-2.127's home
    /// pin, AUTH-1.32's fingerprint index and `IdentityState`'s keyed rows as
    /// laws, and the I2 composition property
    /// `fold(s ++ t) == fold_from(fold(s), t)`.
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
        let mut claim_count = 0usize;

        for case in &cases {
            let subject_was_nonempty = !st.key_set(&case.subject).is_empty();
            let preview = fx.classify(&st, &case.dep);
            let (next, verdict) = fx.step(&st, &case.dep);

            // AUTH-2.57 — classify is exactly the verdict step reaches.
            prop_assert_eq!(&preview, &verdict);
            // Only Honored moves the state (I8 for NotCredential, and every
            // inert verdict leaves the table untouched).
            if !matches!(verdict, Verdict::Honored(_)) {
                prop_assert_eq!(&next, &st);
            }
            // AUTH-2.127 — the home pin as the LAW it is: every honored
            // deposit, of every kind and arm, is homed in its home account's
            // doc 1 — never a second document, never doc 1's version member.
            if matches!(verdict, Verdict::Honored(_)) {
                prop_assert_eq!(&case.dep.home, &case.home_doc_one);
            }
            // I5 — the latch: once the subject's set has EVER been
            // non-empty, every enrollment homed outside its own space is
            // inert (registry-, claimant- and stranger-homed alike).
            if case.kind == ActKind::Enroll
                && subject_was_nonempty
                && case.home_account != case.subject
            {
                prop_assert!(matches!(verdict, Verdict::Inert(_)));
            }

            match &verdict {
                Verdict::Honored(Effect::Genesis { account, keys }) => {
                    // I5 — at most one Honored(Genesis) per account, and
                    // never onto a set that was already non-empty.
                    prop_assert!(!subject_was_nonempty);
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
                    claim_count += 1;
                    prop_assert!(claim_count <= 1);
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
                let set = next.key_set(acct);
                if let Some((_, enrolled)) =
                    set.enrolled().find(|(enrolled_fp, _)| *enrolled_fp == f)
                {
                    prop_assert_eq!(enrolled.anchor, *flag);
                }
                if let Some((_, retired_flag)) =
                    set.retired().find(|(retired_fp, _)| *retired_fp == f)
                {
                    prop_assert_eq!(retired_flag, *flag);
                }
            }
            // AUTH-1.32 — the map key is an INDEX over the value, never a
            // second authority: every enrolled row's key is the fingerprint
            // of the key that row holds. Established by construction in
            // `apply` (AUTH-2.53) and re-checked nowhere on the write path,
            // so this is the only statement of it over a folded table.
            for acct in &accounts {
                for (enrolled_fp, enrolled) in next.key_set(acct).enrolled() {
                    prop_assert_eq!(*enrolled_fp, Fingerprint::of(&enrolled.key));
                }
            }
            // `IdentityState`'s standing invariant — every row is KEYED:
            // `keyed_accounts` never yields an account whose set is empty.
            // The posts' preconditions establish it and nothing on the write
            // path re-checks it, so this is its statement over a folded table.
            for (acct, set) in next.keyed_accounts() {
                prop_assert!(!set.is_empty(), "{:?} holds a row with no key", acct);
            }

            st = next;
        }

        // I2 — `fold(s ++ t) == fold_from(fold(s), t)`, and re-folding the
        // whole stream reproduces the same table (determinism over a fixed
        // ctx and stream).
        let fold_over = |start: &IdentityState, segment: &[Case]| -> IdentityState {
            let mut folded = start.clone();
            for case in segment {
                folded = fx.step(&folded, &case.dep).0;
            }
            folded
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
                prop_assert_eq!(&verdict, &Verdict::NotCredential);
            }
            prop_assert_eq!(&next, &genesis_state);
        }
    }
}
