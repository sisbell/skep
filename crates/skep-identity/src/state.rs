//! `IdentityState` and the fold — AUTH-1.38–1.41, AUTH-2.35, AUTH-2.56–2.60,
//! AUTH-2.62–2.78, AUTH-2.126–2.127 — with the fold's own readings of the
//! seam and its ω projections, private to it, and the doc-1 address, public.

use std::sync::LazyLock;

use im::OrdMap;
use serde::{Deserialize, Serialize};
use skep_address::{checked_inc, parent, Address, Level};

use crate::key::Fingerprint;
use crate::keyset::{Enrolled, KeySet};
use crate::payload::{parse_enroll, parse_retire, Enrollment, PayloadError};
use crate::read::record_bytes;
use crate::seam::FoldCtx;
use crate::shape::{single_address, CredentialKind, LinkDeposit, TypeAddrs};
use crate::verdict::{Effect, Inert, Verdict};

/// The empty set `key_set` answers for an unkeyed or unknown account
/// (AUTH-2.58). Once-only initialization of a `Default` value — the crate's
/// one `std::sync` item (see the crate-level purity note).
static EMPTY_KEY_SET: LazyLock<KeySet> = LazyLock::new(KeySet::default);

/// AUTH-1.38 — the board's key table plus claim: a folded projection,
/// advanced only by [`step`] and never journaled, seated as the engine's
/// World slice and serialized in every checkpoint (AUTH-2.79; the crate-level
/// composition note) — the engine steps it at each credential deposit's
/// commit and a reopen replays it from the last checkpoint that carries it,
/// so no host rebuilds it from the deposits. Account addresses have ONE
/// representation in the slice — both `sets`' keys and `claimant` are
/// `Address` (AUTH-1.39). The serialized shape is AUTH-1.40's compatibility
/// surface — the checkpoints, the engine's `#[serde(default)] identity:
/// Option<IdentityState>`, which the engine writes today, and the
/// cross-mirror `/dump` pin, which it does not yet — and freezes with the
/// first checkpoint a served board writes. `IdentityState` at N is a function
/// of the record stream ≤ N and the fold's frozen constants, and of nothing
/// else (I2, AUTH-2.90).
///
/// Standing invariant — every row of `sets` is KEYED, its enrolled map
/// non-empty: what [`keyed_accounts`] promises, and what makes two states
/// that answer every [`key_set`] and [`claimant`] read alike EQUAL, as values
/// and as serialized bytes. [`step`] establishes it — the genesis post is
/// never empty and no post empties a set (`apply`'s PRECONDITION) — and, like
/// [`KeySet`]'s own, it is re-checked nowhere on this side, so a deserialized
/// value carries it only as its source did.
///
/// [`claimant`]: IdentityState::claimant
/// [`key_set`]: IdentityState::key_set
/// [`keyed_accounts`]: IdentityState::keyed_accounts
/// [`step`]: IdentityState::step
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityState {
    sets: OrdMap<Address, KeySet>,
    claimant: Option<Address>,
}

/// AUTH-2.60 — the bound a host that SEATS the slice implements (the World in
/// AUTH-2.79's cast; a mirror's projection), so identity readers dispatch
/// over the host instead of being handed the slice. The engine's `World`
/// implements it over the slice it carries, and skepd's readers take the
/// slice off whichever World snapshot they hold through it (the crate-level
/// composition note).
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
    /// PRECONDITION — `dep` keeps [`LinkDeposit`]'s: its `home` a REGISTERED
    /// document. Item 3 asks the seam a birth state, and this crate holds no
    /// registration fact to test first, so the registration-first discipline
    /// a publication read carries (PUB-6.37) is `dep`'s constructor's,
    /// discharged before this call.
    ///
    /// PRECONDITION — `types` is the board's ONE [`TypeAddrs`], the SAME value
    /// at every step of one record stream. It is a frozen constant
    /// (`IDENTITY_TYPES`, AUTH-2.90) that reaches the fold as an ARGUMENT
    /// rather than as a `const`, because the three addresses are open
    /// (AUTH-7.1) and this crate is parametric over them — so the constancy is
    /// the CALLER's to supply and nothing here can test it. Two steps given
    /// different values fold one stream against two credential vocabularies,
    /// and [`IdentityState`]'s I2 statement — a function of the record stream
    /// and the fold's frozen constants, and of nothing else — is void, with
    /// every verdict in the run individually correct. skepd holds ONE in a
    /// `static`; a mirror owes the same, having fixed one address form for it
    /// (AUTH-2.125).
    ///
    /// PRECONDITION — `ctx` answers AS OF THE DEPOSIT'S COMMIT, every fact
    /// alike ([`FoldCtx`]'s card) — the point this verdict is ABOUT, and the
    /// other input [`IdentityState`]'s I2 statement rests on beside `types`. A
    /// ctx at head folds an earlier deposit against facts its commit did not
    /// have — a value minted later (AUTH-2.5), a `to` address that became an
    /// account later — and the table built over it is then the head's rather
    /// than the stream's, at every such deposit.
    ///
    /// Total under the same conforming-ctx condition as [`step`], and the two
    /// debug assertions that condition names are reached from here.
    ///
    /// [`step`]: IdentityState::step
    pub fn classify(
        &self,
        types: &TypeAddrs,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit<'_>,
    ) -> Verdict {
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
            CredentialKind::Claim => self.claim_path(ctx, dep, &home_account),
            CredentialKind::Enroll => self.enroll_path(ctx, dep, &home_account),
            CredentialKind::Retire => self.retire_path(ctx, dep, &home_account),
        }
    }

    /// AUTH-2.56/AUTH-2.57 — classify-then-apply (on `Honored`) or self
    /// unchanged; `dep`, `types` and `ctx` owe [`classify`]'s PRECONDITIONS.
    ///
    /// TOTAL under a CONFORMING ctx — one meeting [`Values`]' and [`FoldCtx`]'s
    /// stated obligations: no input a RECORD can carry reaches a panic, and
    /// every refusal travels as a [`Verdict`]. A ctx that breaks an obligation
    /// is the ctx's bug and each site says so: a zero-byte value at a covered
    /// position (AUTH-1.22) debug-asserts in `record_bytes`, and an
    /// element-level ω prefix (AUTH-2.126) debug-asserts in `doc_1_of`. Both
    /// are a broken PRECONDITION, not an exception to this postcondition.
    ///
    /// [`Values`]: crate::Values
    /// [`classify`]: IdentityState::classify
    #[must_use = "step returns the next state and its verdict; it does not modify the receiver"]
    pub fn step(
        &self,
        types: &TypeAddrs,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit<'_>,
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
    /// `is_registered_account` — the seam's [`FoldCtx::is_account`]
    /// (AUTH-2.33) — BESIDE this call.
    pub fn key_set(&self, account: &Address) -> &KeySet {
        self.sets.get(account).unwrap_or(&*EMPTY_KEY_SET)
    }

    /// AUTH-2.56 — the board claimant, `None` while unclaimed; never changes
    /// once `Some` (I6, AUTH-2.101).
    pub fn claimant(&self) -> Option<&Address> {
        self.claimant.as_ref()
    }

    /// AUTH-2.59 — every KEYED account with its set, in ADDRESS ORDER (the
    /// `OrdMap`'s own order): the enumeration the spec builds `/dump`'s
    /// identity section from — a section no dump renders as built, and not
    /// the section the engine's dump gives that name, which is M3's
    /// `authoritative.namespace` rather than this slice.
    /// An unkeyed or unknown account has no row here and [`key_set`] answers
    /// it the empty set — this is not the board's account roster, which is
    /// M3's fact and not this slice's (AUTH-2.58).
    ///
    /// [`key_set`]: IdentityState::key_set
    pub fn keyed_accounts(&self) -> impl Iterator<Item = (&Address, &KeySet)> {
        self.sets.iter()
    }

    /// AUTH-2.62 — the genesis registry:
    /// the COMPUTED FIRST SUB-ACCOUNT `inc(B, 1)` of a BOOTSTRAP-TIER account
    /// `B` (AUTH-2.65) ⇒ `None` — the RES-80 arm AHEAD of the three, the AGENT
    /// SPACE `X.1` the ceremony reserves (RES-64), whose `S` is empty at every
    /// instant and whose every seeding attempt is `NotGenesisRegistry` by
    /// AUTH-2.71's FIRST refusal arm, from any hand, in any session, on every
    /// board, forever; then `Account(D) ⇒ Some(D)`; `Bootstrap ⇒
    /// Some(claimant | A)` (the account's OWN space while the board is
    /// unclaimed, the CLAIMANT's once claimed); a `None` delegator ⇒ `None`.
    /// `None ⇒` NO genesis is ever possible for the address: every seeding
    /// attempt is `Inert(NotGenesisRegistry)` (AUTH-2.63) — for the agent space
    /// the LOAD-BEARING refusal of that space (AUTH-5.87), for a `None`
    /// delegator unreachable for an address M3 admits as an account, BOTH
    /// pinned for totality. Consulted ONLY by the enroll genesis arm
    /// (AUTH-2.64). THE FIRST ARM IS CRATE-LOCAL ARITHMETIC (AUTH-2.62,
    /// RES-80): `parent()` and `inc(·, 1)` over the address, `B`'s tier read
    /// through the EXISTING `delegator` projection over the seam's `owner_of`
    /// — NO seam method added, no M3 query beyond the ω the registry already
    /// consults, AUTH-2.31's four facts unmoved.
    fn genesis_registry(&self, ctx: &impl FoldCtx, subject: &Address) -> Option<Address> {
        match delegator(ctx, subject)? {
            Delegator::Account(d) => {
                // AUTH-2.62's RES-80 arm — `subject == inc(B, 1)` for a
                // BOOTSTRAP-TIER `B` (AUTH-2.65) ⇒ None. `B = parent(subject)`;
                // its tier is `delegator(B) == Bootstrap`; the first-child test
                // is `checked_inc(B, 1) == subject` (k = 1 always preserves T4,
                // so `ok()` is the value; a later child `B·k`, k ≥ 2, and a
                // descendant fail the equality and take `Some(d)`).
                let first_child_of_bootstrap = parent(subject).is_some_and(|b| {
                    checked_inc(&b, 1).ok().as_ref() == Some(subject)
                        && matches!(delegator(ctx, &b), Some(Delegator::Bootstrap))
                });
                if first_child_of_bootstrap {
                    None
                } else {
                    Some(d)
                }
            }
            Delegator::Bootstrap => Some(self.claimant.clone().unwrap_or_else(|| subject.clone())),
        }
    }

    /// AUTH-2.67 — the CLAIM arm, its conditions in the written order (a
    /// `detail` pin, AUTH-2.68 — the cost gradient runs the wrong way and an
    /// implementation MUST NOT reorder cheap-first). The claim carries NO
    /// payload: this arm reads no bytes (AUTH-2.48).
    fn claim_path(
        &self,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit<'_>,
        home_account: &Address,
    ) -> Verdict {
        // 1 — shape: `from = {H}` in address form, `to = ∅` (AUTH-2.48; the
        // fold cannot tell the two empty-`to` wire forms apart, AUTH-2.49).
        if single_address(dep.from).as_ref() != Some(home_account) || !dep.to.is_empty() {
            return Verdict::Inert(Inert::MalformedShape);
        }
        // 2 — the home pin (AUTH-2.127, RES-17), before the delegator read:
        // a wrong-home nested-account claim answers `not_doc_one`, never
        // `claimant_not_top_level`.
        if !homed_in_doc_one(dep, home_account) {
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

    /// AUTH-2.66 item 4 — the arm entry BOTH payload-carrying kinds share, in
    /// the one order AUTH-2.127 pins for them: the shape checks and the one
    /// payload read ([`subject_and_record`]), then the kind's parse, then the
    /// home pin, then the kind's arms. Every adjacency here is a `detail` pin
    /// — a wrong-home deposit whose payload is unparseable answers
    /// `malformed_payload`, never `not_doc_one`; a wrong-home genesis
    /// `not_doc_one`, never `not_genesis_registry` — so the order is written
    /// HERE, once, rather than once per kind. The CLAIM kind does not come
    /// through here: it carries no payload, and it pins its home at a
    /// different point among its own conditions (AUTH-2.67 item 2,
    /// [`claim_path`]).
    ///
    /// The arms get what this path OWNS — the subject and the parsed entries,
    /// by value — and nothing after them reads either, so an honored post
    /// MOVES the subject and the parse's keys into its effect: no key is
    /// copied between the parse and the effect it rides in.
    ///
    /// [`claim_path`]: IdentityState::claim_path
    fn payload_path<T>(
        &self,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit<'_>,
        home_account: &Address,
        parse: impl FnOnce(&[u8]) -> Result<Vec<T>, PayloadError>,
        arms: impl FnOnce(Address, Vec<T>) -> Verdict,
    ) -> Verdict {
        let (subject, bytes) = match subject_and_record(ctx, dep) {
            Ok(found) => found,
            Err(inert) => return Verdict::Inert(inert),
        };
        let entries = match parse(&bytes) {
            Ok(entries) => entries,
            Err(e) => return Verdict::Inert(Inert::MalformedPayload(e)),
        };
        if !homed_in_doc_one(dep, home_account) {
            return Verdict::Inert(Inert::NotDocOne);
        }
        arms(subject, entries)
    }

    /// AUTH-2.66 item 4, ENROLL — the enrollment kind's two rows of
    /// [`payload_path`]: `parse_enroll`, then [`enroll_arms`].
    ///
    /// [`payload_path`]: IdentityState::payload_path
    /// [`enroll_arms`]: IdentityState::enroll_arms
    fn enroll_path(
        &self,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit<'_>,
        home_account: &Address,
    ) -> Verdict {
        self.payload_path(ctx, dep, home_account, parse_enroll, |subject, enrollments| {
            self.enroll_arms(ctx, subject, home_account, enrollments)
        })
    }

    /// AUTH-2.69–2.72 — the enrollment arms, in the written order (hoisting
    /// either cheap refusal test above the genesis arm forks the table,
    /// AUTH-2.72).
    fn enroll_arms(
        &self,
        ctx: &impl FoldCtx,
        subject: Address,
        home_account: &Address,
        enrollments: Vec<Enrollment>,
    ) -> Verdict {
        let set = self.key_set(&subject);
        // AUTH-2.69's `H == A` — the record is homed in the subject's OWN
        // space.
        let own_space = *home_account == subject;
        // Holder arm (AUTH-2.69): `H == A ∧ !S.is_empty()`.
        if own_space && !set.is_empty() {
            // `added` is the entries the set ADMITS — fingerprints it has never
            // held, enrolled or retired — WHATEVER their flags: the enrolling
            // mutator's PRECONDITION, discharged here (I4 AUTH-2.98; I9
            // AUTH-2.104).
            let added: Vec<Enrolled> = enrollments
                .into_iter()
                .filter(|enrollment| set.admits(&Fingerprint::of(&enrollment.key)))
                .map(enrolled_of)
                .collect();
            if added.is_empty() {
                return Verdict::Inert(Inert::NothingChanged);
            }
            return Verdict::Honored(Effect::Enroll {
                account: subject,
                added,
            });
        }
        if set.is_empty() {
            // Genesis arm (AUTH-2.70): `genesis_registry(A) == Some(H)`;
            // fires at most once per account by construction (the set never
            // re-empties — I3 AUTH-2.97, I5 AUTH-2.100). The registry is
            // consulted here ONLY (AUTH-2.64).
            let registry = self.genesis_registry(ctx, &subject);
            if registry.as_ref() == Some(home_account) {
                // THE HANDOFF LATCH (AUTH-2.71), INSIDE the cell the genesis
                // arm would otherwise honor and AHEAD of its post — so
                // AUTH-2.72's written order below is unmoved, and no refusal
                // moves at an account the genesis arm never reached. What the
                // latch IS, scope and comparand, is its own card.
                if self.handoff_latch_fires(ctx, &subject, &enrollments) {
                    return Verdict::Inert(Inert::NotGenesisRegistry);
                }
                let keys: Vec<Enrolled> = enrollments.into_iter().map(enrolled_of).collect();
                return Verdict::Honored(Effect::Genesis {
                    account: subject,
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

    /// AUTH-2.71 — THE HANDOFF LATCH, whole: does it fire for a genesis at
    /// `subject` naming these keys? Two conditions, the SCOPE first, so no
    /// caller can ask half the rule.
    ///
    /// SCOPE — the SUBDIVISIONS alone (`delegator(subject) == Account(_)`),
    /// NEVER the bootstrap-delegated tier (AUTH-2.65), where a person's second
    /// top-level account is a sibling and a same-key genesis is legitimate.
    ///
    /// COMPARAND — any key the genesis names already stands ENROLLED in the
    /// set that OPENS THE ACCOUNT ABOVE `subject` ([`opening_set_above`]): a
    /// handoff gives an account to a party that could not already open it, and
    /// a party that could needs no genesis. The ENROLLED half only (`contains`
    /// reads enrolled-NOW — a retired fingerprint opens nothing, I4
    /// AUTH-2.98, RES-138); a comparand with no non-empty set above answers
    /// `false` (the walk's terminus, RES-137).
    ///
    /// NO new token and NO seam fact: the scope reads the ω the genesis
    /// registry already consults, and the comparand reads `S(·)` at `parent()`
    /// addresses (I2, AUTH-2.90; the token pin, AUTH-2.72).
    ///
    /// [`opening_set_above`]: IdentityState::opening_set_above
    fn handoff_latch_fires(
        &self,
        ctx: &impl FoldCtx,
        subject: &Address,
        enrollments: &[Enrollment],
    ) -> bool {
        if !matches!(delegator(ctx, subject), Some(Delegator::Account(_))) {
            return false;
        }
        match self.opening_set_above(subject) {
            None => false,
            Some(opening) => enrollments
                .iter()
                .any(|enrollment| opening.contains(&Fingerprint::of(&enrollment.key))),
        }
    }

    /// AUTH-2.71 / AUTH-4.30 (i) — the set that OPENS THE ACCOUNT ABOVE `a`:
    /// the parent's set where it is non-empty, else the set of the nearest
    /// account above the parent whose set is not empty — AUTH-4.30 (i)'s walk,
    /// `parent()` arithmetic over `a`'s ACCOUNT-TIER ancestors and no others
    /// (crate-local, no seam fact, the class of `inc(a, 2)` AUTH-2.126 already
    /// takes). It STOPS at the first ancestor that is not an account, and
    /// answers `None` where no account above `a` holds a non-empty set: the
    /// walk's TERMINUS, which AUTH-2.71 takes from AUTH-4.30 (i) and pins FOR
    /// TOTALITY — `step` must be total (AUTH-2.57), and I2 (AUTH-2.90) admits
    /// no band in which one build reads the empty set and honors while another
    /// walks past the account tier.
    ///
    /// skepd's session layer writes the same walk behind AUTH-4.30's
    /// `key_subject`, and its precheck's handoff test takes it too — AUTH-4.30
    /// places that accessor on skepd's surface and AUTH-2.56 fixes this
    /// type's — so the rule is written in both crates, and the two agree
    /// because both stop at the tier. The fold's own posts could not show a
    /// difference, the arm entry's `is_account` seating rows at accounts
    /// alone; a slice deserialized from elsewhere can carry a row at a node,
    /// and neither walk reads it. Every row of `self.sets` is KEYED (the
    /// standing invariant), so a present row is a non-empty opening set; the
    /// `is_empty` filter holds the walk to "whose set is not empty" under a
    /// value whose source did not keep that invariant.
    fn opening_set_above(&self, a: &Address) -> Option<&KeySet> {
        std::iter::successors(parent(a), parent)
            .take_while(|above| above.level() == Level::Account)
            .find_map(|above| self.sets.get(&above).filter(|set| !set.is_empty()))
    }

    /// AUTH-2.66 item 4, RETIRE — the retirement kind's two rows of
    /// [`payload_path`]: `parse_retire`, then [`retire_arms`].
    ///
    /// [`payload_path`]: IdentityState::payload_path
    /// [`retire_arms`]: IdentityState::retire_arms
    fn retire_path(
        &self,
        ctx: &impl FoldCtx,
        dep: &LinkDeposit<'_>,
        home_account: &Address,
    ) -> Verdict {
        self.payload_path(ctx, dep, home_account, parse_retire, |subject, fps| {
            self.retire_arms(subject, home_account, fps)
        })
    }

    /// AUTH-2.74–2.76 — the retirement arms. ANCHOR-BLIND on purpose
    /// (AUTH-2.75): seniority is testimony, a write-path check, never a fold
    /// input. The retirement arms never read `delegator` (AUTH-2.64,
    /// AUTH-2.76).
    fn retire_arms(
        &self,
        subject: Address,
        home_account: &Address,
        fps: Vec<Fingerprint>,
    ) -> Verdict {
        let set = self.key_set(&subject);
        // AUTH-2.74's `H == A` — the record is homed in the subject's OWN
        // space.
        let own_space = *home_account == subject;
        // Holder arm (AUTH-2.74): `H == A ∧ !S.is_empty()`.
        if own_space && !set.is_empty() {
            let removed: Vec<Fingerprint> = fps.into_iter().filter(|fp| set.contains(fp)).collect();
            if removed.is_empty() {
                return Verdict::Inert(Inert::NothingChanged);
            }
            // `removed ⊆ enrolled` and F is duplicate-free (AUTH-2.15), so
            // equal size ⟺ set equality: the WHOLE record is inert (I3).
            if removed.len() == set.enrolled_len() {
                return Verdict::Inert(Inert::WouldEmpty);
            }
            return Verdict::Honored(Effect::Retire {
                account: subject,
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
    /// PRECONDITION — `post` leaves the set NON-EMPTY. This is the ONE place a
    /// row is seated, so it is the one place that obligation is owed, and
    /// nothing here checks it: a closure that leaves the set empty seats an
    /// EMPTY row and voids [`IdentityState`]'s standing invariant —
    /// [`keyed_accounts`] would yield an account holding no key, and two
    /// states answering every [`key_set`] and [`claimant`] read alike would
    /// compare unequal, as values and as checkpoint bytes. HOW each arm of
    /// [`apply`] discharges it is that routine's PRECONDITION.
    ///
    /// [`apply`]: IdentityState::apply
    /// [`keyed_accounts`]: IdentityState::keyed_accounts
    /// [`key_set`]: IdentityState::key_set
    /// [`claimant`]: IdentityState::claimant
    fn post_to_set(&mut self, account: &Address, post: impl FnOnce(&mut KeySet)) {
        let mut set = self.sets.get(account).cloned().unwrap_or_default();
        post(&mut set);
        self.sets.insert(account.clone(), set);
    }

    /// AUTH-2.53 — `apply` reads the effect and DECIDES NOTHING on any arm,
    /// the genesis arm included (no arm reads the payload twice). Map keys
    /// are derived via `Fingerprint::of` on the key inserted, establishing
    /// AUTH-1.32 by construction.
    ///
    /// PRECONDITION — `effect` is one [`classify`] answered for THIS state.
    /// This is where [`KeySet`]'s two mutator preconditions arrive, and it
    /// discharges neither: `Retire`'s `removed` must be a PROPER subset of the
    /// account's enrolled set — the `WouldEmpty` test, AUTH-2.74 — or AUTH-1.36
    /// and I3 are void, and the fingerprints moved in one post are this arm's
    /// whole loop; each key `Enroll`'s `added` and `Genesis`' `keys` post must
    /// be one the set [`admits`](KeySet::admits) at its insert — the holder
    /// arm's filter asks the set before the post, the genesis arm posts into an
    /// empty set, which admits every fingerprint (AUTH-2.70), and
    /// [`parse_enroll`]'s duplicate-free POSTCONDITION keeps the answer across
    /// each post — or AUTH-1.35 and I4 are void on the retired half and I9
    /// (AUTH-2.104) on the enrolled half, a second insert REPLACING the first's
    /// flag. And every set-touching arm must leave the posted set NON-EMPTY —
    /// [`post_to_set`]'s PRECONDITION, where the standing invariant is owed —
    /// by a DIFFERENT route on each. `Genesis`' `keys` are non-empty
    /// ([`parse_enroll`]'s POSTCONDITION, AUTH-2.16); were they not, the post
    /// would seat an EMPTY row, [`keyed_accounts`] would yield an account
    /// holding no key, and the set the genesis arm tests would still be empty,
    /// so that arm could fire again and I5 (AUTH-2.100) would be void.
    /// `Enroll`'s account ALREADY holds a non-empty row, because AUTH-2.69's
    /// arm fires only on `!S.is_empty()` — so an `Enroll` naming an account
    /// with no row is outside this precondition whatever `added` holds, and
    /// `added`'s own non-emptiness is that arm's `NothingChanged` test, not
    /// this one's. `Retire`'s proper-subset clause above carries its half
    /// already: nothing is a proper subset of the empty set, so a `Retire`
    /// cannot reach a rowless account, and a proper subset of a non-empty set
    /// leaves it non-empty. A NEW arm owes the obligation, not one of these
    /// three routes. `Claim` posts no set; it must find `claimant` `None` —
    /// AUTH-2.67 item 4 — or I6 (AUTH-2.101) is void: its post is an
    /// assignment, and it overwrites. [`step`] is the only caller and it passes
    /// `classify`'s own answer.
    ///
    /// [`classify`]: IdentityState::classify
    /// [`keyed_accounts`]: IdentityState::keyed_accounts
    /// [`post_to_set`]: IdentityState::post_to_set
    /// [`step`]: IdentityState::step
    #[must_use = "apply returns the posted state; it does not modify the receiver"]
    fn apply(&self, effect: &Effect) -> IdentityState {
        let mut next = self.clone();
        match effect {
            // The genesis arm posts `enrolled = K` WITHOUT consulting
            // `retired` (AUTH-2.70; sound per AUTH-1.36).
            Effect::Genesis { account, keys } => next.post_to_set(account, |set| {
                for k in keys {
                    set.insert_enrolled(k.clone());
                }
            }),
            Effect::Enroll { account, added } => next.post_to_set(account, |set| {
                for k in added {
                    set.insert_enrolled(k.clone());
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

/// AUTH-2.35 — the crate's own ω projection (never re-implemented outside
/// it): the account a document belongs to, `ctx.owner_of(doc)?.prefix`. A
/// non-folding reader takes `owner_of(doc)?.prefix` itself.
///
/// The answer is whatever prefix ω resolved, at the level
/// [`FoldCtx::owner_of`] fixes: account-level for a document under a
/// registered account principal, node-level for one owned directly by the
/// bootstrap principal. Every use of H in this crate is a comparison or
/// [`doc_1_of`]'s arithmetic, both total at either level — so an arm that
/// ever needs account-hood must ask [`FoldCtx::is_account`] (AUTH-2.33) for
/// it and not presume it here.
fn document_account(ctx: &impl FoldCtx, doc: &Address) -> Option<Address> {
    ctx.owner_of(doc).map(|owner| owner.prefix)
}

/// AUTH-2.35 — the delegator classification `delegator(ctx, a)` projects to.
#[derive(Debug)]
enum Delegator {
    /// The parent's owner is the bootstrap principal — the bootstrap-delegated
    /// tier: every account one separator deep, on every board (AUTH-2.65).
    Bootstrap,
    /// The parent's owner is an account principal (an account delegated
    /// BENEATH an account); carries that owner's prefix.
    Account(Address),
}

/// AUTH-2.35 — the crate's second ω projection (private to the fold): M1
/// `parent(a)` then `owner_of` mapped — `Bootstrap` iff that owner is the
/// bootstrap principal, `Account(prefix)` otherwise, `None` iff the account
/// has no parent or the parent is unowned (unreachable in practice for an
/// address M3 admits as an account, merely total here — AUTH-2.106).
fn delegator(ctx: &impl FoldCtx, a: &Address) -> Option<Delegator> {
    let p = parent(a)?;
    let owner = ctx.owner_of(&p)?;
    Some(if owner.is_bootstrap {
        Delegator::Bootstrap
    } else {
        Delegator::Account(owner.prefix)
    })
}

/// AUTH-2.126 (RES-17) — THE DOC-1 ADDRESS: the address of `a`'s FIRST
/// document, computed FROM THE ACCOUNT ADDRESS ALONE as address arithmetic —
/// `inc(a, 2)` = `a·0·1` under AUTH-2.109's pinned M3 expectation (verified
/// against M1's `inc`: `k = 2` appends one zero then a `1`) — with NO query
/// and NO new seam method; [`FoldCtx`] still answers AUTH-2.31's four facts.
/// The home pin (AUTH-2.127) compares credential homes against this address.
///
/// The operand is an ω prefix, so the level obligation this arithmetic rests
/// on is [`FoldCtx::owner_of`]'s, stated there: a node- or account-level
/// address. An element-level one debug-asserts.
///
/// PUBLIC, though AUTH-2.126 declares it crate-private: M3 computes the same
/// slot as `skep_namespace::first_document_address`, a crate this one cannot
/// depend on (AUTH-2.1), so the two agree by value and not by one function.
/// skepd's suite, which links both, holds them equal at every account-level
/// operand (`crates/skepd/tests/it/doc_one.rs`) and states where they part:
/// at a node-level prefix this arithmetic still answers `N·0·1`, the node's
/// first ACCOUNT, where M3's answers `None`. The difference moves no
/// verdict: a home is a document and `N·0·1` is not, so the pin refuses
/// there either way.
pub fn doc_1_of(a: &Address) -> Address {
    match checked_inc(a, 2) {
        Ok(doc) => doc,
        Err(_) => {
            // The TA5a gate refuses k = 2 only for an Element-level operand;
            // no conforming ω answers an element-level principal prefix
            // (M3 registers principals at node/account prefixes). Total,
            // never a panic (AUTH-2.57): the returned prefix is document-of
            // nothing, so every home comparison against it refuses.
            debug_assert!(
                a.level() != Level::Element,
                "doc_1_of on an element-level prefix — no conforming ctx answers one"
            );
            a.clone()
        }
    }
}

/// AUTH-2.127 (RES-17) — THE home pin, in one place: a credential link is
/// honored only in its account's FIRST document (`doc_1_of`, AUTH-2.126).
/// The operand is the HOME'S account, never the subject. All three arms test
/// it and each answers `Inert::NotDocOne` itself; WHERE each tests it is that
/// arm's own precedence pin (AUTH-2.66 for enroll/retire, AUTH-2.67 item 2
/// for the claim), which is what its call site says.
fn homed_in_doc_one(dep: &LinkDeposit<'_>, home_account: &Address) -> bool {
    *dep.home == doc_1_of(home_account)
}

/// AUTH-2.66 item 4, ENROLL/RETIRE arm entry: `!from.is_empty()`
/// (AUTH-2.47 — an empty `from` names no bytes ⇒ `MalformedShape`, pinned
/// AHEAD of the parser: it never reaches `record_bytes` or answers a payload
/// token) and `A = single_address(to)` with `ctx.is_account(A)`, else
/// `MalformedShape` (`single_address` is NOT applied to `from` — AUTH-2.27);
/// then the one payload read (AUTH-2.36). Shape checks precede
/// `record_bytes` (AUTH-2.66: a two-span `to` beside an over-cap `from` is
/// `malformed_shape`, never `too_large`).
fn subject_and_record(
    ctx: &impl FoldCtx,
    dep: &LinkDeposit<'_>,
) -> Result<(Address, Vec<u8>), Inert> {
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

/// AUTH-2.52 — what an honored enrollment KEEPS from a parsed entry: the key
/// and the flag it enters under, MOVED out of the entry. The label is
/// informational (AUTH-1.23) and is not a fold input, so it drops here with
/// the rest of the entry — the one place that is decided.
fn enrolled_of(enrollment: Enrollment) -> Enrolled {
    Enrolled {
        key: enrollment.key,
        anchor: enrollment.anchor,
    }
}

#[cfg(test)]
mod tests {
    use super::{doc_1_of, IdentityState};
    use crate::key::{PublicKey, ALG_MLDSA65_ED25519, MLDSA65_KEY_LEN};
    use crate::keyset::{Enrolled, KeySet};
    use skep_address::{validate, Nat, Tumbler};

    fn addr(comps: &[u32]) -> skep_address::Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
            .expect("T4-valid")
    }

    /// AUTH-2.126/AUTH-2.109 — the doc-1 form is `A·0·1` (`inc(A, 2)`).
    #[test]
    fn doc_1_is_account_dot_0_dot_1() {
        assert_eq!(doc_1_of(&addr(&[1, 1, 0, 5])), addr(&[1, 1, 0, 5, 0, 1]));
        // A nested account's first document sits under the nested prefix.
        assert_eq!(
            doc_1_of(&addr(&[1, 1, 0, 3, 1])),
            addr(&[1, 1, 0, 3, 1, 0, 1])
        );
        // A node-level prefix (the bootstrap owner's) still answers totally.
        assert_eq!(doc_1_of(&addr(&[1, 1])), addr(&[1, 1, 0, 1]));
    }

    /// AUTH-2.71 / AUTH-4.30 (i) — the handoff latch's comparand is found by
    /// AUTH-4.30 (i)'s walk, over the ACCOUNT tier alone. A keyed row at a
    /// NODE — one no fold posts, the arm entry admitting account-level
    /// subjects alone, so a row only a slice deserialized from elsewhere can
    /// carry — lies past the walk's terminus and is never the comparand, while
    /// the same set seated at the account between that node and the
    /// subdivision is.
    #[test]
    fn the_opening_set_walk_stops_at_the_account_tier() {
        let key = PublicKey::from_halves(ALG_MLDSA65_ED25519, &[0; MLDSA65_KEY_LEN], &[0; 32])
            .expect("the tag-1 row's widths");
        let mut keyed = KeySet::default();
        keyed.insert_enrolled(Enrolled { key, anchor: true });
        let subdivision = addr(&[1, 1, 0, 5, 2]);
        let mut st = IdentityState::genesis();
        st.sets.insert(addr(&[1, 1]), keyed.clone());
        assert_eq!(
            st.opening_set_above(&subdivision),
            None,
            "a node's row lies past the terminus"
        );
        st.sets.insert(addr(&[1, 1, 0, 5]), keyed.clone());
        assert_eq!(
            st.opening_set_above(&subdivision),
            Some(&keyed),
            "an account's row opens it"
        );
    }

    /// AUTH-2.71 / AUTH-4.30 (i) — the comparand is "the set of the nearest
    /// account above the parent whose set is NOT EMPTY". An account row
    /// holding the EMPTY set — one no fold posts, the standing invariant
    /// keeping every row keyed, so a row only a slice deserialized from
    /// elsewhere can carry, its re-check the host's (AUTH-1.33) — opens
    /// nothing: `key_set` answers that account the empty set either way, and
    /// the walk climbs past it to the keyed account above. A walk that took
    /// the first PRESENT row would answer the empty set there, and the latch
    /// comparing against it would honor a genesis naming the very key that
    /// opens the account above — where skepd's walk, reading each set through
    /// `key_set`, climbs past the row as this one does.
    #[test]
    fn the_opening_set_walk_passes_over_an_empty_row() {
        let key = PublicKey::from_halves(ALG_MLDSA65_ED25519, &[0; MLDSA65_KEY_LEN], &[0; 32])
            .expect("the tag-1 row's widths");
        let mut keyed = KeySet::default();
        keyed.insert_enrolled(Enrolled { key, anchor: true });
        let mut st = IdentityState::genesis();
        st.sets.insert(addr(&[1, 1, 0, 5]), keyed.clone());
        st.sets.insert(addr(&[1, 1, 0, 5, 2]), KeySet::default());
        assert_eq!(
            st.opening_set_above(&addr(&[1, 1, 0, 5, 2, 5])),
            Some(&keyed),
            "an empty row opens nothing: the walk climbs past it"
        );
    }
}
