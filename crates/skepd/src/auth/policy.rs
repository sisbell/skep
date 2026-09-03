//! The write-path policy surface (AUTH part 03): the credential type
//! addresses, op classification, the refusal producers at their pinned lock
//! scopes, and the precheck's ordered slots.

use std::sync::LazyLock;

use skep_address::{validate, Address, Level, Nat, Span, Tumbler};
use skep_febe::Op;
use skep_identity::{
    CredentialKind, Effect, IdentityState, Inert, LinkDeposit, TypeAddrs, Verdict,
};
use skep_links::{enc, HasLinks, SlotArg};
use skep_namespace::{first_document_address, HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

use super::fold::WorldCtx;
use super::{LockRead, LockWrite};
use crate::World;

/// The enrolled-set cap (RES-57, AUTH-3.57): daemon POLICY — a
/// config-visible constant, never a fold constant — `Enroll` arm only,
/// `Genesis` exempt. Raisable later without format consequence — but not
/// without CPU consequence: the enrolled set is what
/// [`super::session::handshake`] walks in full on every signed
/// `POST /session` attempt, so raising this raises that unauthenticated
/// route's per-attempt work linearly. The budget is written on
/// [`MAX_GENESIS_KEYS`], which bounds the same quantity on the arm this
/// cap exempts.
pub(crate) const MAX_ENROLLED_KEYS: usize = 16;

/// The seeding hand's own bound (daemon POLICY, the same standing as
/// [`MAX_ENROLLED_KEYS`]). RES-57 exempts `Genesis` from the ENROLLED
/// SET's cap — an account seeded past it keeps its keys — and what is
/// bounded here is ONE RECORD's key count, which is a different quantity:
/// it is what [`super::session::find_signer`] walks, in full, on every
/// signed `POST /session` attempt, and that route is unauthenticated and
/// reachable from any page.
///
/// The budget is N × `verify_strict` against the two cheap requests that
/// buy it — one `GET /challenge`, one `POST /session`, neither carrying a
/// credential. At [`MAX_ENROLLED_KEYS`] the bill is order 800 µs,
/// commensurate with the frame parse beside it; at the record's own
/// [`skep_identity::MAX_RECORD_BYTES`] bound it is order 40 ms, which the
/// worker pool cannot absorb. "No cutoff, ever" (AUTH-4.33) is what makes
/// the cap belong HERE, at the deposit, rather than at the verification.
///
/// The pre-claim window is the reachable one and the exposure is
/// permanent: slot (7) is arm-blind, so a bare genesis plant on a claimed
/// board dies there, while anything seeded before the claim can be retired
/// only by an anchor session of that account — whose keys the planter
/// chose.
pub(crate) const MAX_GENESIS_KEYS: usize = MAX_ENROLLED_KEYS;

/// The most keys slot (4) point-decodes: ONE past the cap slot (5) applies.
/// A record past that cap is refused whatever the rest decode to, so every
/// decode beyond it is work an over-cap frame buys and never spends — order
/// 800 decompressions at the record's own upstream
/// [`skep_identity::MAX_RECORD_BYTES`], order 10 µs each, held under
/// `credential_lock.write()` AND the serialization lock, bought by a
/// 150-byte deposit naming one pre-inserted atom.
///
/// The two caps are equal by definition today. If they ever diverge this
/// must be the LARGER, or an over-cap record on the larger arm re-opens the
/// same bill.
const MAX_DECODED_KEYS: usize = MAX_GENESIS_KEYS + 1;

/// The three credential type addresses — AUTH-7.1 horn B's allocation,
/// recorded for the commons-seeding table (see the build report): subspace
/// 3 of the ghost document `1.1.0.1.0.1`, ordinals 1–3 in the order
/// enroll · retire · claim.
///
/// Why subspace 3 discharges AUTH-3.70's unreachability obligation with no
/// store edit: content V-spec RESOLUTION only ever yields I-spans in the
/// CONTENT subspace (subspace 1) of real documents — M3's content mints are
/// the resolution's whole codomain — and no M3 door mints into any
/// document's subspace 3 at all, so these names are never allocated and no
/// resolved span can equal their subtree spans. `deposits_credential_link`
/// therefore answers false for every `Resolve` type slot without resolving
/// anything, which is exactly AUTH-2.61's lock-free classifier.
pub(crate) const T_ENROLL: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 1];
pub(crate) const T_RETIRE: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 2];
pub(crate) const T_CLAIM: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 3];

fn addr_of(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c)))
        .expect("the credential type components are nonempty");
    validate(t).expect("the credential type addresses are T4-valid by construction")
}

/// The ONE `TypeAddrs` (`IDENTITY_TYPES`, AUTH-2.79) — an I2 frozen
/// constant; every classifier and the fold read this instance.
pub(crate) fn identity_types() -> &'static TypeAddrs {
    static TYPES: LazyLock<TypeAddrs> = LazyLock::new(|| {
        TypeAddrs::new(addr_of(&T_ENROLL), addr_of(&T_RETIRE), addr_of(&T_CLAIM))
    });
    &TYPES
}

/// One address-form slot in M7's own deposited form — `enc(addrs)`. The
/// ONE spelling, so [`deposits_credential_link`]'s classification and
/// [`DepositSpans::of`]'s deposit read a type slot through the same call:
/// two of the three readings the obligation on that classifier rests on
/// become one, and only the rebuild's (M7's stored slot) stays separate.
fn addr_spans(addrs: &[Address]) -> Vec<Span> {
    enc(addrs.iter()).spans().cloned().collect()
}

/// A slot's spans in M7's own deposited form: [`addr_spans`] for the
/// address form; `None` for `Resolve` — a resolved slot can never name a
/// credential type (the allocation above), so classification never
/// resolves.
fn slotarg_kind(s: &SlotArg) -> Option<CredentialKind> {
    match s {
        SlotArg::Addrs(addrs) => identity_types().kind_of(&addr_spans(addrs)),
        SlotArg::Resolve(_) => None,
    }
}

/// AUTH-2.61 — op classification: the op's OWN type slot, no world read,
/// so the lock is chosen before any lock is taken. True for the three
/// deposit-shaped ops whose type slot names a credential type; a `Nullify`
/// deposits nothing (its class is `nullify_refusal`'s, under the read
/// lock).
///
/// OBLIGATION, and the one this predicate cannot check: `true` for exactly
/// the deposits [`precheck`]'s classify and
/// [`crate::auth::fold::canonical_identity`] will read as credential-typed.
/// All three read the type slot's spans, and two of the three readings are
/// structural rather than claimed — this one and [`DepositSpans::of`] both
/// go through [`addr_spans`], the one spelling of `enc(addrs)`. Only the
/// rebuild's stays a claim: it reads M7's stored slot, which records `enc`
/// verbatim. The subspace-3 allocation above is what keeps a `Resolve` slot
/// out of the codomain. A FALSE NEGATIVE is the divergence this module
/// cannot detect: the deposit commits through the plain path with no gate
/// and no fold step, so the world holds a credential the live fold never
/// saw, `key_set` answers one thing until restart and another after it, and
/// nothing reports either. A false positive reaches [`precheck`]'s defect
/// arm at the classify line.
///
/// EXHAUSTIVE with no `_` arm, the treatment [`crate::write_path::write_meta`]
/// already gives the read/write partition: the non-deposit arm is written
/// out, so a new `Op` fails to compile here until someone decides whether it
/// can carry a credential type slot. A wildcard would default that decision
/// to `false` — the false negative above, which is the one answer this
/// module cannot detect being wrong.
pub(crate) fn deposits_credential_link(op: &Op) -> bool {
    match op {
        Op::MakeLink { ty, .. } => slotarg_kind(ty).is_some(),
        Op::Emit { ty, .. } => {
            let spans: Vec<Span> = ty.spans().cloned().collect();
            identity_types().kind_of(&spans).is_some()
        }
        Op::EditLink { successor, .. } => slotarg_kind(&successor.ty).is_some(),
        // Every other op deposits no link at all, so none can be
        // credential-typed — including `Nullify`, whose class is
        // `nullify_refusal`'s under the read lock.
        Op::CreateNewDocument { .. }
        | Op::Delegate { .. }
        | Op::RegisterNode { .. }
        | Op::Fork
        | Op::NextAccountPrefix { .. }
        | Op::PrincipalPrefix { .. }
        | Op::Insert { .. }
        | Op::Delete { .. }
        | Op::Copy { .. }
        | Op::Rearrange { .. }
        | Op::Version { .. }
        | Op::Nullify { .. }
        | Op::AssertSup { .. }
        | Op::ReadLink { .. }
        | Op::FollowLink { .. }
        | Op::RetrieveV { .. }
        | Op::RetrieveDocVSpan { .. }
        | Op::RetrieveDocVSpanSet { .. }
        | Op::ShowOrigin { .. }
        | Op::ShowDeletions { .. }
        | Op::Compare { .. }
        | Op::FindDocsContaining { .. }
        | Op::Image { .. }
        | Op::FindLinksV { .. }
        | Op::FindLinksFtt { .. }
        | Op::CountV { .. }
        | Op::CountFtt { .. }
        | Op::WindowV { .. }
        | Op::WindowFtt { .. }
        | Op::RetrieveEndsets { .. }
        | Op::Project { .. }
        | Op::DiscoverableFrom { .. }
        | Op::DeleteOrphans { .. }
        | Op::InClaims { .. }
        | Op::OutClaims { .. } => false,
    }
}

/// The daemon-side refusal vocabulary (AUTH-3.53). Every one marshals as
/// `code: credential_refused, disposition: permanent, detail: token()`
/// (AUTH-3.54 — `Permanent` UNIFORMLY; the remedy lives in the face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialRefusal {
    /// The fold's own verdict — produced by `precheck`, slot (3).
    Inert(Inert),
    /// Slot (1), ahead of the write lock.
    EmitNotMakeLink,
    /// Slot (4).
    UndecodableKey,
    /// The NULLIFY class, under the read lock, outside slots (1)–(8).
    NullifyNotRetraction,
    /// Slot (6).
    AnchorSessionRequired,
    /// Slot (2), ahead of the write lock.
    ResolvedFrom,
    /// Slot (5) — present because the build takes the cap (RES-57, at 16).
    TooManyEnrolled,
    /// The MINT class, on the plain path.
    MintHomeFirst,
    /// Slot (7), and the plain path's publish gate (RES-26).
    SignedSessionRequired,
    /// Slot (8), and the plain path's pre-claim admission gate (RES-27).
    ClaimFirst,
}

impl CredentialRefusal {
    /// The wire `detail` token: the fold arm delegates to `Inert::token()`
    /// (the payload arm is the one `malformed_payload:<sub>` join,
    /// AUTH-2.55); the daemon-side tokens are hand-spelled here and only
    /// here.
    pub fn token(&self) -> String {
        match self {
            CredentialRefusal::Inert(Inert::MalformedPayload(p)) => {
                format!("malformed_payload:{}", p.token())
            }
            CredentialRefusal::Inert(i) => i.token().to_string(),
            CredentialRefusal::EmitNotMakeLink => "emit_not_make_link".into(),
            CredentialRefusal::UndecodableKey => "undecodable_key".into(),
            CredentialRefusal::NullifyNotRetraction => "nullify_not_retraction".into(),
            CredentialRefusal::AnchorSessionRequired => "anchor_session_required".into(),
            CredentialRefusal::ResolvedFrom => "resolved_from".into(),
            CredentialRefusal::TooManyEnrolled => "too_many_enrolled".into(),
            CredentialRefusal::MintHomeFirst => "mint_home_first".into(),
            CredentialRefusal::SignedSessionRequired => "signed_session_required".into(),
            CredentialRefusal::ClaimFirst => "claim_first".into(),
        }
    }
}

// ── op_shape_refusal — slots (1)–(2), lock-free (AUTH-3.4–3.6) ───────────

/// Slots (1) `emit_not_make_link` and (2) `resolved_from`, evaluated (1)
/// then (2), reading the op's OWN slots and nothing else — evaluated
/// beside `deposits_credential_link` and AHEAD of `credential_lock.write()`
/// (AUTH-3.5): a refusal here never takes the write lock.
pub(crate) fn op_shape_refusal(op: &Op) -> Option<CredentialRefusal> {
    match op {
        // (1) — every credential-typed emit, unconditionally: M7's dedup
        // could hand a phantom ack for an act key_set never shows.
        Op::Emit { .. } => Some(CredentialRefusal::EmitNotMakeLink),
        // (2) — a credential deposit whose from OR to entity slot is a
        // Resolve, either of them, regardless of emptiness.
        Op::MakeLink { from, to, .. } => {
            if matches!(from, SlotArg::Resolve(_)) || matches!(to, SlotArg::Resolve(_)) {
                Some(CredentialRefusal::ResolvedFrom)
            } else {
                None
            }
        }
        // (2) — every credential edit_link, unconditionally: the successor
        // endsets are V-spec-only as built (AUTH-3.18's dead rule stands
        // recorded there; the op never reaches deposit construction).
        Op::EditLink { .. } => Some(CredentialRefusal::ResolvedFrom),
        _ => None,
    }
}

// ── nullify_refusal — the NULLIFY class, read lock (AUTH-3.7–3.9) ────────

/// `Some(NullifyNotRetraction)` iff `op` is a `Nullify` whose target's
/// `readlink` type slot is credential-typed AND the shape token is the
/// caller's to receive. The op-kind test is INSIDE and first (one match
/// arm for the common case); `world` MUST be the snapshot taken under the
/// read guard for this request — the guard argument is that contract's
/// cheap half.
///
/// RES-32's entitlement scope is the second conjunct: on a CLAIMED board
/// the shape token reaches only the owner of the `home` the retraction
/// would land in, so anyone else answers `None` here, falls through to
/// execute, and receives ω's own `not_owner` — indistinguishable from its
/// non-credential answer. Pre-claim the order stands for every caller.
pub(crate) fn nullify_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    identity: &IdentityState,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    let Op::Nullify { home, target } = op else { return None };
    let link = world.links().readlink(target)?;
    let spans: Vec<Span> = link.type_slot().spans().cloned().collect();
    identity_types().kind_of(&spans)?;
    if identity.claimant().is_some() && !world.m3().is_effective_owner(principal, home) {
        return None;
    }
    Some(CredentialRefusal::NullifyNotRetraction)
}

// ── mint_home_refusal — the MINT class (AUTH-3.10–3.14) ──────────────────

/// AUTH-3.68's `has_documents(account)`, built over M3's PUBLIC read
/// surface: the account's document chain is empty iff the slot it opens at
/// — `first_document_address(A)` — holds no registered document. Exact
/// because that chain is contiguous from its first ordinal, which is M3's
/// own guarantee and M3's own arithmetic. A subject that anchors no
/// document chain answers `None` there, hence `false` here.
pub(crate) fn has_documents(world: &World, account: &Address) -> bool {
    first_document_address(account)
        .is_some_and(|first| world.m3().is_registered_document(&first))
}

/// `Some(MintHomeFirst)` iff `op` is a document-minting op OTHER than
/// `create_new_document` and the subject account's chain is empty. The
/// subject is `principal_prefix(p)` THEN an account-hood test — never
/// `key_subject` (AUTH-3.11); a subject that is not an account answers
/// `None` and no arm fires. Reads the op's KIND and the PRINCIPAL and
/// nothing else — never a fork/version source (AUTH-3.13).
///
/// `world` MUST be the snapshot taken under the read guard for this
/// request; the guard argument is that contract's cheap half.
pub(crate) fn mint_home_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    if !matches!(op, Op::Fork | Op::Version { .. }) {
        return None;
    }
    let subject = world.m3().principal_prefix(principal)?;
    if world.m3().entity_level(subject) != Some(Level::Account) {
        return None;
    }
    if has_documents(world, subject) {
        None
    } else {
        Some(CredentialRefusal::MintHomeFirst)
    }
}

// ── board_state_refusal — the two mode-complementary gates (AUTH-3.78) ───

/// v1's publication read for the PUBLISH gate (RES-26): the one
/// born-published class this build can compute is the mechanical home mint
/// — an account's doc 1 (publication.md rule 1's home-mint law). Flagless
/// mints resolve DRAFT (AUTH-3.67's scoping), and no wire flag exists yet,
/// so a document is published here iff it IS its account's doc 1. The
/// fold's own `is_published` stays wired constant `true` (AUTH-2.117) and
/// agrees on every credential home, all of which the home pin confines to
/// doc 1.
fn is_published_v1(world: &World, doc: &Address) -> bool {
    world
        .m3()
        .effective_owner_prefix(doc)
        .and_then(first_document_address)
        .is_some_and(|first| first == *doc)
}

/// The plain path's one producer for the two board-state gates, dispatched
/// on claimed-ness (AUTH-3.78): once claimed, the public-permanent gate
/// (RES-26, `signed_session_required`); in UNCLAIMED the pre-claim
/// admission gate (RES-27, `claim_first`). Exact under the read guard: the
/// claim commits only under `credential_lock.write()`.
///
/// `world` and `identity` MUST be the pair taken under the read guard for
/// this request; the guard argument is that contract's cheap half.
pub(crate) fn board_state_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    identity: &IdentityState,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&skep_identity::Fingerprint>,
) -> Option<CredentialRefusal> {
    if identity.claimant().is_some() {
        publish_gate(world, op, principal, signer)
    } else {
        pre_claim_gate(world, op, principal)
    }
}

/// RES-26 (AUTH-3.79–3.81): on a claimed board, an op whose write lands in
/// the published world is accepted only from a signed session. Domain per
/// input form: a flagless `version` reads `published(d_src)`; a homed
/// write reads `published(home)`. Flagless `create`/`fork` resolve draft
/// (outside), `delegate`/`register_node`/`nullify` present no input form,
/// and the mechanical home mint is exempt by AUTH-3.80. Registration and ω
/// stand AHEAD: the gate evaluates only registered addresses the caller
/// owns, so an unregistered or foreign home answers `execute`'s own code.
fn publish_gate(
    world: &World,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&skep_identity::Fingerprint>,
) -> Option<CredentialRefusal> {
    if signer.is_some() {
        return None;
    }
    let homed = |home: &Address| -> Option<CredentialRefusal> {
        let m3 = world.m3();
        if m3.is_registered_document(home)
            && is_published_v1(world, home)
            && m3.is_effective_owner(principal, home)
        {
            Some(CredentialRefusal::SignedSessionRequired)
        } else {
            None
        }
    };
    match op {
        Op::Version { d_src } => {
            if world.m3().is_registered_document(d_src) && is_published_v1(world, d_src) {
                Some(CredentialRefusal::SignedSessionRequired)
            } else {
                None
            }
        }
        Op::Insert { doc, .. }
        | Op::Delete { doc, .. }
        | Op::Copy { doc, .. }
        | Op::Rearrange { doc, .. } => homed(doc),
        Op::MakeLink { home, .. } | Op::Emit { home, .. } | Op::AssertSup { home, .. } => {
            homed(home)
        }
        Op::EditLink { d_s, .. } => homed(d_s),
        _ => None,
    }
}

/// RES-27/27a (AUTH-3.82–3.83): an UNCLAIMED daemon admits only the claim
/// ceremony's own op SHAPES — per op, by shape, no ceremony state machine:
/// the `delegate` from principal 0, the mechanical home mint, and the
/// record atom's `insert` into the depositing account's own doc 1. The
/// credential deposits' pre-claim cells are the precheck's slot (8), never
/// this producer's. Everything else refuses `claim_first`, bare and signed
/// sessions alike.
fn pre_claim_gate(world: &World, op: &Op, principal: PrincipalId) -> Option<CredentialRefusal> {
    let admitted = match op {
        Op::Delegate { .. } => principal == BOOTSTRAP_PRINCIPAL,
        Op::CreateNewDocument { account } => !has_documents(world, account),
        Op::Insert { doc, .. } => world
            .m3()
            .principal_prefix(principal)
            .and_then(first_document_address)
            .is_some_and(|first| first == *doc),
        // Fail-CLOSED, which is why this arm may be a wildcard where
        // `deposits_credential_link`'s may not: a new op defaults to
        // `claim_first` and costs its author one decision, rather than
        // defaulting to admission on an unclaimed board.
        _ => false,
    };
    if admitted {
        None
    } else {
        Some(CredentialRefusal::ClaimFirst)
    }
}

// ── plain_refusal — the plain path's ordered producers (AUTH-3.35) ───────

/// The plain path's three producers in their pinned order: the NULLIFY
/// class, then the MINT class, then the mode-complementary board-state
/// pair. The ORDER is the pin, so it lives here with the producers rather
/// than at the call site — the same treatment [`precheck`] gives the
/// credential path's eight slots.
///
/// `world` and `identity` MUST be the pair taken under the read guard for
/// this request; the guard argument each producer takes is that contract's
/// cheap half.
pub(crate) fn plain_refusal(
    lock: &LockRead<'_>,
    world: &World,
    identity: &IdentityState,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&skep_identity::Fingerprint>,
) -> Option<CredentialRefusal> {
    nullify_refusal(lock, world, identity, op, principal)
        .or_else(|| mint_home_refusal(lock, world, op, principal))
        .or_else(|| board_state_refusal(lock, world, identity, op, principal, signer))
}

// ── precheck — slots (3)–(8), under the write lock (AUTH-3.15–3.19) ──────

/// The owned span form of one would-be deposit, built from the frame
/// VERBATIM (AUTH-3.17): `home` verbatim, `from`/`to`/`ty` as
/// address-form spans via M7's `enc`, in endset order.
pub(crate) struct DepositSpans {
    pub home: Address,
    pub from: Vec<Span>,
    pub to: Vec<Span>,
    pub ty: Vec<Span>,
}

impl DepositSpans {
    /// `Some` only for a `MakeLink` whose three slots are all address-form
    /// — the one op that reaches deposit construction (`Emit` dies at slot
    /// (1), `EditLink` at slot (2), a `Nullify` is `nullify_refusal`'s).
    pub fn of(op: &Op) -> Option<DepositSpans> {
        let Op::MakeLink { home, from, to, ty } = op else { return None };
        let slot = |s: &SlotArg| -> Option<Vec<Span>> {
            match s {
                SlotArg::Addrs(a) => Some(addr_spans(a)),
                SlotArg::Resolve(_) => None,
            }
        };
        Some(DepositSpans {
            home: home.clone(),
            from: slot(from)?,
            to: slot(to)?,
            ty: slot(ty)?,
        })
    }

    pub fn deposit(&self) -> LinkDeposit<'_> {
        LinkDeposit { home: &self.home, from: &self.from, to: &self.to, ty: &self.ty }
    }
}

/// The precheck's answer: the refusal, or nothing. The previewed effect is
/// deliberately NOT returned — the committed tail re-derives from the same
/// deposit under the same guard
/// ([`crate::auth::fold::IdentityFold::step_committed`]), so handing it
/// forward would be a second path to one state change, and a signature
/// that offers it invites exactly that.
///
/// The `Ok` taken at the classify line is AUTH-3.19's defect arm —
/// `NotCredential` there is unreachable by construction (the classifier
/// that chose this path reads the same spans through the same
/// [`addr_spans`]); if reached, this assert fires, the write passes with
/// no slot (4)–(8), and the caller runs the committed tail like any other,
/// where the fold's own step reaches the same `NotCredential` verdict and
/// does not advance — so AUTH-3.19's "no fold feed" holds of the OUTCOME
/// and not of the CALL, and in a debug build `step_committed`'s assert
/// fires second.
///
/// `world` and `identity` MUST be the pair taken under the write guard for
/// this request; the guard argument is that contract's cheap half.
pub(crate) fn precheck(
    _lock: &LockWrite<'_>,
    world: &World,
    identity: &IdentityState,
    dep: &DepositSpans,
    signer: Option<&skep_identity::Fingerprint>,
) -> Result<(), CredentialRefusal> {
    // (3) — the classify preview's verdict (AUTH-2.57): the fold's own
    // order — kind, home account, publication, the per-kind arm.
    let verdict = identity.classify(identity_types(), &WorldCtx(world), &dep.deposit());
    let effect = match verdict {
        Verdict::NotCredential => {
            debug_assert!(false, "classify answered NotCredential on a classified deposit");
            return Ok(());
        }
        Verdict::Inert(i) => return Err(CredentialRefusal::Inert(i)),
        Verdict::Honored(e) => e,
    };
    // (4) — undecodable_key: a valid-hex non-point key can never sign; the
    // fold accepts syntax, the daemon extends the courtesy. The decode is
    // the SAME one `super::session::verify` performs, so the courtesy is
    // exact rather than an approximation of it. It is BOUNDED by
    // [`MAX_DECODED_KEYS`] — the discipline [`crate::codec`]'s `room`
    // states, applied to the one slot whose input this module cannot cap.
    //
    // CONSEQUENCE: a record that is BOTH over-cap and carries an
    // undecodable key past [`MAX_ENROLLED_KEYS`] answers
    // `too_many_enrolled` where the slot order alone would say
    // `undecodable_key`. It is refused either way, permanently, in the same
    // vocabulary and by the same function; what changes is which of two
    // true things it is told.
    let keys_decodable = |keys: &[skep_identity::Enrolled]| {
        keys.iter().take(MAX_DECODED_KEYS).all(|e| super::verifying_key(&e.key).is_some())
    };
    match &effect {
        Effect::Enroll { added, .. } if !keys_decodable(added) => {
            return Err(CredentialRefusal::UndecodableKey)
        }
        Effect::Genesis { keys, .. } if !keys_decodable(keys) => {
            return Err(CredentialRefusal::UndecodableKey)
        }
        _ => {}
    }
    // (5) — the enrolled-set cap (RES-57): Enroll arm only, Genesis exempt
    // from the SET's cap.
    if let Effect::Enroll { account, added } = &effect {
        if identity.key_set(account).enrolled().count() + added.len() > MAX_ENROLLED_KEYS {
            return Err(CredentialRefusal::TooManyEnrolled);
        }
    }
    // (5, second arm) — the seeding hand's own record ([`MAX_GENESIS_KEYS`]):
    // a different quantity from the set's cap, and the one every signed
    // handshake attempt walks. Refused in the SAME vocabulary, which is
    // honest for it and adds no wire code.
    if let Effect::Genesis { keys, .. } = &effect {
        if keys.len() > MAX_GENESIS_KEYS {
            return Err(CredentialRefusal::TooManyEnrolled);
        }
    }
    // (6) — the anchor gate (AUTH-3.20–3.23): an anchor retirement or a
    // post-genesis anchor-flagged enrollment needs a session an anchor of
    // that account established; a bare session never satisfies it; the
    // record is refused WHOLE. Genesis is exempt (the seeding hand records
    // the initial set, flags included).
    let anchor_act = match &effect {
        Effect::Retire { account, removed } => {
            let set = identity.key_set(account);
            removed.iter().any(|fp| set.is_anchor(fp)).then_some(account)
        }
        Effect::Enroll { account, added } => {
            added.iter().any(|e| e.anchor).then_some(account)
        }
        _ => None,
    };
    if let Some(account) = anchor_act {
        let set = identity.key_set(account);
        if !signer.is_some_and(|fp| set.is_anchor(fp)) {
            return Err(CredentialRefusal::AnchorSessionRequired);
        }
    }
    // (7)/(8) — the mode-disjoint board-state slots.
    let claimed = identity.claimant().is_some();
    if claimed {
        // (7) — arm-blind: Genesis is NOT exempt here; a bare genesis
        // plant on a claimed board dies at this slot.
        if signer.is_none() {
            return Err(CredentialRefusal::SignedSessionRequired);
        }
    } else if !matches!(effect, Effect::Genesis { .. } | Effect::Claim { .. }) {
        // (8) — the pre-claim admission gate's deposit cell, evaluated on
        // the slot-(3) preview: only the ceremony's own deposits pass.
        return Err(CredentialRefusal::ClaimFirst);
    }
    Ok(())
}

/// The five reserved subtree spans overlap nothing the credential types
/// name: the identity types live in subspace 3 while the shipped classes
/// sit at content positions 1..=5 — pinned so a change to either
/// allocation fails here rather than in a fold.
#[cfg(test)]
mod tests {
    use skep_address::subtree_of;

    use super::*;

    #[test]
    fn identity_types_are_distinct_and_recognized() {
        let types = identity_types();
        let enroll_span = subtree_of(addr_of(&T_ENROLL).tumbler());
        assert_eq!(types.kind_of(&[enroll_span]), Some(CredentialKind::Enroll));
        let retire_span = subtree_of(addr_of(&T_RETIRE).tumbler());
        assert_eq!(types.kind_of(&[retire_span]), Some(CredentialKind::Retire));
        let claim_span = subtree_of(addr_of(&T_CLAIM).tumbler());
        assert_eq!(types.kind_of(&[claim_span]), Some(CredentialKind::Claim));
        // A shipped reserved type (ghost position 1, the content subspace)
        // is NOT a credential type.
        let retired = subtree_of(addr_of(&[1, 1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(types.kind_of(&[retired]), None);
    }

    /// AUTH-3.70's conformance expression in miniature: a content-I-span
    /// type slot answers no credential kind — a resolved span's start is a
    /// mintable content position, never a subspace-3 name.
    #[test]
    fn a_content_span_ty_is_never_credential() {
        // Content position 1 of some ordinary doc: <doc>.0.1.1.
        let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(identity_types().kind_of(&[content]), None);
    }
}
