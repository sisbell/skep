//! Shared test fixture: a pure `Values`/`FoldCtx` stub over a small board,
//! address/span builders, and deposit constructors. The ctx stub is the "ctx
//! stub" the invariants' Test clauses name (AUTH-2.102); type addresses are
//! test placeholders — the real three are the engine's `IDENTITY_TYPES`
//! (AUTH-2.79, open per AUTH-7.1; this crate is parametric over them).

#![allow(dead_code)]
#![allow(clippy::new_without_default)]

use std::collections::{BTreeMap, BTreeSet};

use skep_address::{is_prefix, subtree_of, validate, Address, Nat, Span, Tumbler};
use skep_identity::{
    encode_enroll, encode_retire, Effect, Enrollment, Fingerprint, FoldCtx, IdentityState, Inert,
    LinkDeposit, Owner, PublicKey, TypeAddrs, Values, Verdict,
};

// ---------------------------------------------------------------- builders

pub fn tum(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn addr(comps: &[u32]) -> Address {
    validate(tum(comps)).expect("test addresses are T4-valid")
}

/// The unit subtree span of the address at `comps` — the shape `enc(&[T])`
/// records for an address-form slot.
pub fn unit(comps: &[u32]) -> Span {
    subtree_of(&tum(comps))
}

/// The content position `home·0·1·ord` (T7 content subspace = 1).
pub fn content_pos(home: &Address, ord: u32) -> Tumbler {
    let mut comps: Vec<Nat> = home.tumbler().iter().cloned().collect();
    comps.push(Nat::from(0u32));
    comps.push(Nat::from(1u32));
    comps.push(Nat::from(ord));
    Tumbler::new(comps).expect("nonempty")
}

/// A width tumbler of `len` components, all zero except the last = `n`.
pub fn width_at_last(len: usize, n: u32) -> Tumbler {
    let mut comps = vec![Nat::from(0u32); len];
    comps[len - 1] = Nat::from(n);
    Tumbler::new(comps).expect("nonempty")
}

/// A span covering `n` content positions of `home` starting at `start_ord`.
pub fn content_run(home: &Address, start_ord: u32, n: u32) -> Span {
    let start = content_pos(home, start_ord);
    let len = start.len();
    Span::new(start, width_at_last(len, n)).expect("positive last-component width")
}

// ---------------------------------------------------------------- the board

pub const NODE: &[u32] = &[1, 1];
/// Commons account; its first document homes the type addresses.
pub const COMMONS: &[u32] = &[1, 1, 0, 1];
/// The claimant-to-be (bootstrap tier).
pub const CLM: &[u32] = &[1, 1, 0, 2];
/// A delegator account (bootstrap tier).
pub const ORG: &[u32] = &[1, 1, 0, 3];
/// An account delegated BENEATH `ORG` (its parent is an account, so its
/// delegator is `Account(ORG)` — AUTH-2.65).
pub const NESTED: &[u32] = &[1, 1, 0, 3, 1];
/// An ordinary bootstrap-tier account.
pub const ACCT_A: &[u32] = &[1, 1, 0, 5];
/// Another bootstrap-tier account.
pub const ACCT_B: &[u32] = &[1, 1, 0, 6];

/// Placeholder credential type addresses in the commons doc's link subspace
/// (AUTH-7.1 leaves the real ones to commons-seeding).
pub const T_ENROLL: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 1];
pub const T_RETIRE: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 2];
pub const T_CLAIM: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 3];

pub fn doc_of(acct: &[u32], d: u32) -> Address {
    let mut comps = acct.to_vec();
    comps.push(0);
    comps.push(d);
    addr(&comps)
}

/// The account's first document `A·0·1` (AUTH-2.126's arithmetic).
pub fn doc1(acct: &[u32]) -> Address {
    doc_of(acct, 1)
}

/// A second document of the account — the home pin's refused residence.
pub fn doc2(acct: &[u32]) -> Address {
    doc_of(acct, 2)
}

// ---------------------------------------------------------------- the ctx

/// Pure world stub: values as-of are whatever the test minted (M4's
/// `value_at`), ω is longest registered prefix, publication is per-doc.
#[derive(Clone, Default)]
pub struct TestCtx {
    pub values: BTreeMap<Tumbler, Vec<u8>>,
    /// Registered principal prefixes: `(prefix, is_bootstrap)`.
    pub owners: Vec<(Address, bool)>,
    pub accounts: BTreeSet<Address>,
    /// Docs NOT published (default: everything published).
    pub unpublished: BTreeSet<Address>,
    /// Flip the whole board unpublished (the I7 ctx).
    pub all_unpublished: bool,
}

impl Values for TestCtx {
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]> {
        self.values.get(at).map(Vec::as_slice)
    }
}

impl FoldCtx for TestCtx {
    fn owner_of(&self, a: &Address) -> Option<Owner> {
        self.owners
            .iter()
            .filter(|(prefix, _)| is_prefix(prefix.tumbler(), a.tumbler()))
            .max_by_key(|(prefix, _)| prefix.tumbler().len())
            .map(|(prefix, boot)| Owner {
                prefix: prefix.clone(),
                is_bootstrap: *boot,
            })
    }

    fn is_account(&self, a: &Address) -> bool {
        self.accounts.contains(a)
    }

    fn is_published(&self, doc: &Address) -> bool {
        !self.all_unpublished && !self.unpublished.contains(doc)
    }
}

// ---------------------------------------------------------------- deposits

/// An owned deposit; `link()` borrows it as the fold's `LinkDeposit`.
pub struct Dep {
    pub home: Address,
    pub from: Vec<Span>,
    pub to: Vec<Span>,
    pub ty: Vec<Span>,
}

impl Dep {
    pub fn link(&self) -> LinkDeposit<'_> {
        LinkDeposit {
            home: &self.home,
            from: &self.from,
            to: &self.to,
            ty: &self.ty,
        }
    }
}

pub struct Fixture {
    pub ctx: TestCtx,
    pub types: TypeAddrs,
    next_ord: BTreeMap<Address, u32>,
}

impl Fixture {
    pub fn new() -> Fixture {
        let mut ctx = TestCtx::default();
        ctx.owners.push((addr(NODE), true));
        for acct in [COMMONS, CLM, ORG, NESTED, ACCT_A, ACCT_B] {
            ctx.owners.push((addr(acct), false));
        }
        for acct in [CLM, ORG, NESTED, ACCT_A, ACCT_B] {
            ctx.accounts.insert(addr(acct));
        }
        let types = TypeAddrs::new(addr(T_ENROLL), addr(T_RETIRE), addr(T_CLAIM));
        Fixture {
            ctx,
            types,
            next_ord: BTreeMap::new(),
        }
    }

    /// Mints `parts` as consecutive one-atom content positions of `home`;
    /// answers one unit span per atom, in mint order.
    pub fn mint(&mut self, home: &Address, parts: &[&[u8]]) -> Vec<Span> {
        let mut spans = Vec::new();
        for part in parts {
            let ord = self.next_ord.entry(home.clone()).or_insert(1);
            let pos = content_pos(home, *ord);
            self.ctx.values.insert(pos.clone(), part.to_vec());
            spans.push(subtree_of(&pos));
            *ord += 1;
        }
        spans
    }

    /// The next unminted ordinal of `home` (for building past-the-mint spans).
    pub fn next_ord(&self, home: &Address) -> u32 {
        self.next_ord.get(home).copied().unwrap_or(1)
    }

    pub fn enroll_dep(&mut self, home: &Address, to_acct: &[u32], payload: &[u8]) -> Dep {
        let from = self.mint(home, &[payload]);
        Dep {
            home: home.clone(),
            from,
            to: vec![unit(to_acct)],
            ty: vec![unit(T_ENROLL)],
        }
    }

    pub fn retire_dep(&mut self, home: &Address, to_acct: &[u32], payload: &[u8]) -> Dep {
        let from = self.mint(home, &[payload]);
        Dep {
            home: home.clone(),
            from,
            to: vec![unit(to_acct)],
            ty: vec![unit(T_RETIRE)],
        }
    }

    /// A claim deposit: `from = {claimant}` (address form), `to = ∅`, no
    /// payload (AUTH-2.48).
    pub fn claim_dep(&self, home: &Address, claimant: &[u32]) -> Dep {
        Dep {
            home: home.clone(),
            from: vec![unit(claimant)],
            to: vec![],
            ty: vec![unit(T_CLAIM)],
        }
    }

    pub fn step(&self, st: &IdentityState, dep: &Dep) -> (IdentityState, Verdict) {
        st.step(&self.types, &self.ctx, &dep.link())
    }

    pub fn classify(&self, st: &IdentityState, dep: &Dep) -> Verdict {
        st.classify(&self.types, &self.ctx, &dep.link())
    }
}

// ---------------------------------------------------------------- payloads

/// Deterministic test key `i`.
pub fn key(i: u8) -> PublicKey {
    PublicKey::Ed25519([i; 32])
}

/// Deterministic test key over a wide index (for many-key records).
pub fn keyn(i: u32) -> PublicKey {
    let mut raw = [0u8; 32];
    raw[28..].copy_from_slice(&i.to_be_bytes());
    PublicKey::Ed25519(raw)
}

pub fn fp(i: u8) -> Fingerprint {
    Fingerprint::of(&key(i))
}

pub fn enr(i: u8, anchor: bool) -> Enrollment {
    Enrollment::new(key(i), anchor, None).expect("label-free enrollment")
}

pub fn enroll_payload(entries: &[(u8, bool)]) -> Vec<u8> {
    let es: Vec<Enrollment> = entries.iter().map(|&(i, anchor)| enr(i, anchor)).collect();
    encode_enroll(&es)
}

pub fn retire_payload(idxs: &[u8]) -> Vec<u8> {
    let fps: Vec<Fingerprint> = idxs.iter().map(|&i| fp(i)).collect();
    encode_retire(&fps)
}

// ---------------------------------------------------------------- verdicts

/// The wire-shaped token of an inert verdict: the join skepd writes, built
/// from the two authorities it joins — `Inert::token()` and, on the payload
/// arm, `PayloadError::token()` (AUTH-2.55, AUTH-1.28). No fold token name is
/// spelled here.
pub fn token_of(v: &Verdict) -> Option<String> {
    match v {
        Verdict::Inert(i @ Inert::MalformedPayload(e)) => {
            Some(format!("{}:{}", i.token(), e.token()))
        }
        Verdict::Inert(i) => Some(i.token().to_owned()),
        _ => None,
    }
}

#[track_caller]
pub fn assert_token(v: &Verdict, want: &str) {
    match token_of(v) {
        Some(got) => assert_eq!(got, want, "wrong inert token"),
        None => panic!(
            "expected Inert({want}), got {}",
            if matches!(v, Verdict::Honored(_)) {
                "Honored"
            } else {
                "NotCredential"
            }
        ),
    }
}

#[track_caller]
pub fn assert_honored(v: &Verdict) -> &Effect {
    match v {
        Verdict::Honored(effect) => effect,
        Verdict::Inert(i) => panic!("expected Honored, got Inert({})", i.token()),
        Verdict::NotCredential => panic!("expected Honored, got NotCredential"),
    }
}

/// Seed `acct` by an own-space pre-claim genesis in its doc 1.
pub fn seed_own(fx: &mut Fixture, st: &IdentityState, acct: &[u32], entries: &[(u8, bool)]) -> IdentityState {
    let dep = fx.enroll_dep(&doc1(acct), acct, &enroll_payload(entries));
    let (next, v) = fx.step(st, &dep);
    assert_honored(&v);
    next
}

/// Claim the board as `acct` (must already hold keys).
pub fn claim_as(fx: &mut Fixture, st: &IdentityState, acct: &[u32]) -> IdentityState {
    let dep = fx.claim_dep(&doc1(acct), acct);
    let (next, v) = fx.step(st, &dep);
    assert_honored(&v);
    next
}
