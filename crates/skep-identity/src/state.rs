//! `IdentityState` and the fold — AUTH-1.38–1.41, AUTH-2.56–2.60,
//! AUTH-2.62–2.78, AUTH-2.126–2.127.

use std::sync::LazyLock;

use im::OrdMap;
use serde::{Deserialize, Serialize};
use skep_address::Address;

use crate::key::Fingerprint;
use crate::keyset::{Enrolled, KeySet};
use crate::payload::{parse_enroll, parse_retire, Enrollment};
use crate::read::record_bytes;
use crate::seam::{delegator, doc_1_of, document_account, Delegator, FoldCtx};
use crate::shape::{single_address, CredentialKind, LinkDeposit, TypeAddrs};
use crate::verdict::{Effect, Inert, Verdict};

/// The empty set `key_set` answers for an unkeyed or unknown account
/// (AUTH-2.58). Once-only initialization of a `Default` value — the crate's
/// one `std::sync` item (see the crate-level purity note).
static EMPTY_KEY_SET: LazyLock<KeySet> = LazyLock::new(KeySet::default);

/// AUTH-1.38 — the board's key table plus claim: a World slice and a folded
/// projection, serialized in checkpoints, advanced only by [`step`], never
/// journaled. Account addresses have ONE representation in the slice — both
/// `sets`' keys and `claimant` are `Address` (AUTH-1.39). The serialized
/// shape is a compatibility surface (the checkpoints, the engine's
/// `#[serde(default)] identity: Option<IdentityState>`, the cross-mirror
/// `/dump` pin) and freezes with the first checkpoint a v1 board writes
/// (AUTH-1.40). `IdentityState` at N is a function of the record stream ≤ N
/// and the fold's frozen constants, and of nothing else (I2, AUTH-2.90).
///
/// [`step`]: IdentityState::step
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityState {
    sets: OrdMap<Address, KeySet>,
    claimant: Option<Address>,
}

/// The engine seats [`IdentityState`] in its `World` (AUTH-2.79–2.88), and
/// `skep_kernel::WorldState` demands `Send + Sync + 'static`. NOTHING in this
/// crate names that bound, so a field that revoked it would break the
/// ENGINE's build, at a trait error naming `World` rather than the field that
/// caused it. The promise is checked here instead, beside the fields — one
/// assertion covering `KeySet`, `Enrolled`, `PublicKey` and `Fingerprint`
/// transitively.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<IdentityState>();
};

/// AUTH-2.60 — the bound identity readers dispatch under, wherever the slice
/// rides (the World; a mirror's projection): M10's `key_set` row and skepd's
/// policy read through it.
pub trait HasIdentity {
    /// The identity slice.
    fn identity(&self) -> &IdentityState;
}

impl IdentityState {
    /// AUTH-1.41 — `genesis()` equals `default()`.
    pub fn genesis() -> IdentityState {
        IdentityState::default()
    }

    /// AUTH-2.57 — the verdict [`step`] would reach, WITHOUT applying it:
    /// the daemon's precheck and the mirror's oracle. Evaluated at the
    /// deposit's commit in AUTH-2.66's order — a `detail` pin:
    ///
    /// 1. `kind = types.kind_of(dep.ty)`, else `NotCredential`;
    /// 2. `H = document_account(ctx, home)`, else `MalformedShape`;
    /// 3. `!ctx.is_published(home)` ⇒ `Inert(Unpublished)` — publication
    ///    runs BEFORE the per-kind shape checks (a draft-homed deposit whose
    ///    `to` is two spans is `unpublished`, never `malformed_shape`);
    /// 4. the per-kind arm — claim (AUTH-2.67) or enroll/retire
    ///    (AUTH-2.69–2.76); every other deposit is AUTH-2.77's.
    ///
    /// [`step`]: IdentityState::step
    pub fn classify(&self, types: &TypeAddrs, ctx: &impl FoldCtx, dep: &LinkDeposit) -> Verdict {
        // 1 — kind (AUTH-2.66 item 1).
        let Some(kind) = types.kind_of(dep.ty) else {
            return Verdict::NotCredential;
        };
        // 2 — the home's account (AUTH-2.66 item 2).
        let Some(home_account) = document_account(ctx, dep.home) else {
            return Verdict::Inert(Inert::MalformedShape);
        };
        // 3 — publication (AUTH-2.66 item 3; I7, AUTH-2.102).
        if !ctx.is_published(dep.home) {
            return Verdict::Inert(Inert::Unpublished);
        }
        // 4 — the per-kind arm.
        match kind {
            CredentialKind::Claim => self.claim_arm(ctx, dep, &home_account),
            CredentialKind::Enroll => self.enroll_path(ctx, dep, &home_account),
            CredentialKind::Retire => self.retire_path(ctx, dep, &home_account),
        }
    }

    /// AUTH-2.56/AUTH-2.57 — classify-then-apply (on `Honored`) or self
    /// unchanged. Total; never panics.
    pub fn step(
        &self,
        types: &TypeAddrs,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit,
    ) -> (IdentityState, Verdict) {
        let verdict = self.classify(types, ctx, dep);
        let next = match &verdict {
            Verdict::Honored(effect) => self.apply(effect),
            _ => self.clone(),
        };
        (next, verdict)
    }

    /// AUTH-2.58 — the account's set; the EMPTY set for an unkeyed or
    /// unknown account. Account-hood is NOT a fact of this slice: a reader
    /// that needs it (the wire row's `not_an_account`) reads M3's
    /// `is_account` BESIDE this call.
    pub fn key_set(&self, account: &Address) -> &KeySet {
        self.sets.get(account).unwrap_or(&*EMPTY_KEY_SET)
    }

    /// AUTH-2.56 — the board claimant, `None` while unclaimed; never changes
    /// once `Some` (I6, AUTH-2.101).
    pub fn claimant(&self) -> Option<&Address> {
        self.claimant.as_ref()
    }

    /// AUTH-2.59 — every KEYED account with its set, in ADDRESS ORDER (the
    /// `OrdMap`'s own order); `/dump`'s identity section is built from this.
    /// An unkeyed or unknown account has no row here and [`key_set`] answers
    /// it the empty set — this is not the board's account roster, which is
    /// M3's fact and not this slice's (AUTH-2.58).
    ///
    /// [`key_set`]: IdentityState::key_set
    pub fn keyed_accounts(&self) -> impl Iterator<Item = (&Address, &KeySet)> {
        self.sets.iter()
    }

    /// AUTH-2.62 — the genesis registry:
    /// `Account(D) ⇒ Some(D)`; `Bootstrap ⇒ Some(claimant | A)` (the
    /// account's OWN space while the board is unclaimed, the CLAIMANT's once
    /// claimed); `None ⇒ None` (no genesis ever possible — every seeding
    /// attempt `NotGenesisRegistry`, AUTH-2.63; unreachable for an address
    /// M3 admits as an account, pinned for totality). Consulted ONLY by the
    /// enroll genesis arm (AUTH-2.64).
    fn genesis_registry(&self, ctx: &impl FoldCtx, subject: &Address) -> Option<Address> {
        match delegator(ctx, subject)? {
            Delegator::Account(d) => Some(d),
            Delegator::Bootstrap => Some(self.claimant.clone().unwrap_or_else(|| subject.clone())),
        }
    }

    /// AUTH-2.67 — the CLAIM arm, its conditions in the written order (a
    /// `detail` pin, AUTH-2.68 — the cost gradient runs the wrong way and an
    /// implementation MUST NOT reorder cheap-first). The claim carries NO
    /// payload: this arm reads no bytes (AUTH-2.48).
    fn claim_arm(&self, ctx: &impl FoldCtx, dep: &LinkDeposit, home_account: &Address) -> Verdict {
        // 1 — shape: `from = {H}` in address form, `to = ∅` (AUTH-2.48; the
        // fold cannot tell the two empty-`to` wire forms apart, AUTH-2.49).
        if single_address(dep.from).as_ref() != Some(home_account) || !dep.to.is_empty() {
            return Verdict::Inert(Inert::MalformedShape);
        }
        // 2 — the home pin (AUTH-2.127, RES-17), before the delegator read:
        // a wrong-home nested-account claim answers `not_doc_one`, never
        // `claimant_not_top_level`.
        if *dep.home != doc_1_of(home_account) {
            return Verdict::Inert(Inert::NotDocOne);
        }
        // 3 — the delegator: `Some(Account(_))` and `None` alike refuse.
        if !matches!(delegator(ctx, home_account), Some(Delegator::Bootstrap)) {
            return Verdict::Inert(Inert::ClaimantNotTopLevel);
        }
        // 4 — first-wins (AUTH-2.68: a keyless top-level claim on a claimed
        // board answers `already_claimed`, never `claimant_keyless`).
        if self.claimant.is_some() {
            return Verdict::Inert(Inert::AlreadyClaimed);
        }
        // 5 — a keyless claimant cannot claim.
        if self.key_set(home_account).is_empty() {
            return Verdict::Inert(Inert::ClaimantKeyless);
        }
        // 6 — post: `claimant = Some(H)`.
        Verdict::Honored(Effect::Claim {
            account: home_account.clone(),
        })
    }

    /// AUTH-2.66 item 4, ENROLL: arm entry (shape, then the one payload
    /// read, then parse), then the home pin AHEAD of the account comparisons
    /// (AUTH-2.127 — a wrong-home deposit whose payload is unparseable
    /// answers `malformed_payload`, never `not_doc_one`; a wrong-home
    /// genesis `not_doc_one`, never `not_genesis_registry`), then the arms.
    fn enroll_path(
        &self,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit,
        home_account: &Address,
    ) -> Verdict {
        let (subject, bytes) = match subject_and_record(ctx, dep) {
            Ok(found) => found,
            Err(inert) => return Verdict::Inert(inert),
        };
        let enrollments = match parse_enroll(&bytes) {
            Ok(enrollments) => enrollments,
            Err(e) => return Verdict::Inert(Inert::MalformedPayload(e)),
        };
        if *dep.home != doc_1_of(home_account) {
            return Verdict::Inert(Inert::NotDocOne);
        }
        self.enroll_arms(ctx, &subject, home_account, &enrollments)
    }

    /// AUTH-2.69–2.72 — the enrollment arms, in the written order (hoisting
    /// either cheap refusal test above the genesis arm forks the table,
    /// AUTH-2.72).
    fn enroll_arms(
        &self,
        ctx: &impl FoldCtx,
        subject: &Address,
        home_account: &Address,
        enrollments: &[Enrollment],
    ) -> Verdict {
        let set = self.key_set(subject);
        // AUTH-2.69's `H == A` — the record is homed in the subject's OWN
        // space.
        let own_space = home_account == subject;
        // Holder arm (AUTH-2.69): `H == A ∧ !S.is_empty()`.
        if own_space && !set.is_empty() {
            // A line naming an already-enrolled or retired fingerprint is
            // outside `added` WHATEVER its flag (I4 AUTH-2.98; I9 AUTH-2.104).
            let added: Vec<Enrolled> = enrollments
                .iter()
                .filter(|k| {
                    let fp = Fingerprint::of(&k.key);
                    !set.contains(&fp) && !set.retired_contains(&fp)
                })
                .map(enrolled_of)
                .collect();
            if added.is_empty() {
                return Verdict::Inert(Inert::NothingChanged);
            }
            return Verdict::Honored(Effect::Enroll {
                account: subject.clone(),
                added,
            });
        }
        if set.is_empty() {
            // Genesis arm (AUTH-2.70): `genesis_registry(A) == Some(H)`;
            // fires at most once per account by construction (the set never
            // re-empties — I3 AUTH-2.97, I5 AUTH-2.100). The registry is
            // consulted here ONLY (AUTH-2.64).
            let registry = self.genesis_registry(ctx, subject);
            if registry.as_ref() == Some(home_account) {
                let keys: Vec<Enrolled> = enrollments.iter().map(enrolled_of).collect();
                return Verdict::Honored(Effect::Genesis {
                    account: subject.clone(),
                    keys,
                });
            }
            // Refusal arms (AUTH-2.71), conditions in the WRITTEN order
            // (AUTH-2.72: registry == None BEFORE H == A — where both hold
            // the token is `not_genesis_registry`, never `no_holder`).
            if registry.is_none() {
                return Verdict::Inert(Inert::NotGenesisRegistry);
            }
            if own_space {
                return Verdict::Inert(Inert::NoHolder);
            }
            return Verdict::Inert(Inert::NotGenesisRegistry);
        }
        // The LATCH arm (AUTH-2.71): `!S.is_empty() ∧ H != A` — a genesis
        // attempt on a seeded account; every later delegator-homed record is
        // inert forever (I5, AUTH-2.100).
        Verdict::Inert(Inert::NotGenesisRegistry)
    }

    /// AUTH-2.66 item 4, RETIRE: arm entry, parse, home pin, arms — the
    /// mirror of [`enroll_path`] over `parse_retire`.
    ///
    /// [`enroll_path`]: IdentityState::enroll_path
    fn retire_path(
        &self,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit,
        home_account: &Address,
    ) -> Verdict {
        let (subject, bytes) = match subject_and_record(ctx, dep) {
            Ok(found) => found,
            Err(inert) => return Verdict::Inert(inert),
        };
        let fps = match parse_retire(&bytes) {
            Ok(fps) => fps,
            Err(e) => return Verdict::Inert(Inert::MalformedPayload(e)),
        };
        if *dep.home != doc_1_of(home_account) {
            return Verdict::Inert(Inert::NotDocOne);
        }
        self.retire_arms(&subject, home_account, &fps)
    }

    /// AUTH-2.74–2.76 — the retirement arms. ANCHOR-BLIND on purpose
    /// (AUTH-2.75): seniority is testimony, a write-path check, never a fold
    /// input. The retirement arms never read `delegator` (AUTH-2.64,
    /// AUTH-2.76).
    fn retire_arms(
        &self,
        subject: &Address,
        home_account: &Address,
        fps: &[Fingerprint],
    ) -> Verdict {
        let set = self.key_set(subject);
        // AUTH-2.74's `H == A` — the record is homed in the subject's OWN
        // space.
        let own_space = home_account == subject;
        // Holder arm (AUTH-2.74): `H == A ∧ !S.is_empty()`.
        if own_space && !set.is_empty() {
            let removed: Vec<Fingerprint> =
                fps.iter().filter(|fp| set.contains(fp)).copied().collect();
            if removed.is_empty() {
                return Verdict::Inert(Inert::NothingChanged);
            }
            // `removed ⊆ enrolled` and F is duplicate-free (AUTH-2.15), so
            // equal size ⟺ set equality: the WHOLE record is inert (I3).
            if removed.len() == set.enrolled_len() {
                return Verdict::Inert(Inert::WouldEmpty);
            }
            return Verdict::Honored(Effect::Retire {
                account: subject.clone(),
                removed,
            });
        }
        // Refusal arms (AUTH-2.76): own-space on a never-keyed set, else the
        // One rule — no ancestor retires a holder's keys.
        if own_space {
            return Verdict::Inert(Inert::NoHolder);
        }
        Verdict::Inert(Inert::NotHolderRetirement)
    }

    /// Post one effect's change into `account`'s set: an account with no row
    /// starts from the EMPTY set (AUTH-2.58's answer, made a real row the
    /// moment an effect touches it), and the amended set is seated back.
    /// Every set-touching arm of [`apply`] posts through here, so how a row
    /// is fetched, defaulted and re-seated is decided in ONE place.
    ///
    /// [`apply`]: IdentityState::apply
    fn post_to_set(&mut self, account: &Address, post: impl FnOnce(&mut KeySet)) {
        let mut set = self.sets.get(account).cloned().unwrap_or_default();
        post(&mut set);
        self.sets.insert(account.clone(), set);
    }

    /// AUTH-2.53 — `apply` reads the effect and DECIDES NOTHING on any arm,
    /// the genesis arm included (no arm reads the payload twice). Map keys
    /// are derived via `Fingerprint::of` on the key inserted, establishing
    /// AUTH-1.32 by construction.
    fn apply(&self, effect: &Effect) -> IdentityState {
        let mut next = self.clone();
        match effect {
            // The genesis arm posts `enrolled = K` WITHOUT consulting
            // `retired` (AUTH-2.70; sound per AUTH-1.36).
            Effect::Genesis { account, keys } => next.post_to_set(account, |set| {
                for k in keys {
                    set.insert_enrolled(*k);
                }
            }),
            Effect::Enroll { account, added } => next.post_to_set(account, |set| {
                for k in added {
                    set.insert_enrolled(*k);
                }
            }),
            Effect::Retire { account, removed } => next.post_to_set(account, |set| {
                for fp in removed {
                    // Each fingerprint carries the flag it was enrolled
                    // under (AUTH-2.74's post, AUTH-1.30).
                    set.move_to_retired(fp);
                }
            }),
            Effect::Claim { account } => next.claimant = Some(account.clone()),
        }
        next
    }
}

/// AUTH-2.66 item 4, ENROLL/RETIRE arm entry: `!from.is_empty()`
/// (AUTH-2.47 — an empty `from` names no bytes ⇒ `MalformedShape`, pinned
/// AHEAD of the parser: it never reaches `record_bytes` or answers a payload
/// token) and `A = single_address(to)` with `ctx.is_account(A)`, else
/// `MalformedShape` (`single_address` is NOT applied to `from` — AUTH-2.27);
/// then the one payload read (AUTH-2.36). Shape checks precede
/// `record_bytes` (AUTH-2.66: a two-span `to` beside an over-cap `from` is
/// `malformed_shape`, never `too_large`).
fn subject_and_record(ctx: &impl FoldCtx, dep: &LinkDeposit) -> Result<(Address, Vec<u8>), Inert> {
    if dep.from.is_empty() {
        return Err(Inert::MalformedShape);
    }
    let subject = match single_address(dep.to) {
        Some(subject) if ctx.is_account(&subject) => subject,
        _ => return Err(Inert::MalformedShape),
    };
    let bytes = record_bytes(ctx, dep.home, dep.from).map_err(Inert::MalformedPayload)?;
    Ok((subject, bytes))
}

/// AUTH-2.52 — what an honored enrollment KEEPS from a parsed line: the key
/// and the flag it enters under. The label is informational (AUTH-1.23) and
/// is not a fold input, so it stops here — the one place that is decided.
fn enrolled_of(k: &Enrollment) -> Enrolled {
    Enrolled {
        key: k.key,
        anchor: k.anchor,
    }
}
