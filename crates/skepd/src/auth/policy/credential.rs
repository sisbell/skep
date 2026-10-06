//! The CREDENTIAL sequence's producers (AUTH-3.37): slots (1)–(2),
//! lock-free and ahead of the credential write lock ([`op_shape_refusal`] —
//! with the credential deposit's `replaces` fence beside them, BW-04), and
//! the precheck's slots (3)–(8) under it ([`precheck`]), with the caps
//! slot (5) applies, the address tests slot (6) and the claim's own
//! admission read, and — inside slot (7)'s claimed arm — THE RECORD GRADE'S
//! CHECK ([`record_grade_check`]; signed ops, 2a): the record's own `sig`,
//! verified at its `make_link` under the set that opens its home.

use skep_address::{checked_inc, ordinal, parent, Address, Nat, Span};
use skep_febe::Op;
use skep_identity::{
    canonical_record, parse_record_value, record_bytes, single_address, Effect, Enrolled,
    Enrollment, Fingerprint, IdentityState, Inert, LinkDeposit, PublicKey, RecordEntry, Verdict,
    ALG_FNDSA512_PREVIEW_ED25519,
};
use skep_links::SlotArg;
use skep_namespace::{system_account, HasM3};

use skep_engine::types::IDENTITY_TYPES;

use super::{addr_spans, deposits_credential_link, AttestFault, CredentialRefusal};
use crate::auth::entry;
use crate::auth::session::{keyed_above, opening_account, HybridSig, Scope};
use crate::auth::LockWrite;
use crate::World;

/// The enrolled-set cap (RES-57, AUTH-3.57): daemon POLICY — a
/// config-visible constant, never a fold constant — `Enroll` arm only,
/// `Genesis` exempt. Raisable later without format consequence — but not
/// without CPU consequence: the enrolled set is what
/// [`crate::auth::session::handshake`] walks in full on every signed
/// `POST /session` attempt, so raising this raises that unauthenticated
/// route's per-attempt work linearly. The budget is written on
/// [`MAX_GENESIS_KEYS`], which bounds the same quantity on the arm this
/// cap exempts.
const MAX_ENROLLED_KEYS: usize = 16;

/// The seeding hand's own bound (daemon POLICY, the same standing as
/// [`MAX_ENROLLED_KEYS`]). RES-57 exempts `Genesis` from the ENROLLED
/// SET's cap — an account seeded past it keeps its keys — and what is
/// bounded here is ONE RECORD's key count, which is a different quantity:
/// it is what `session::find_signer` walks, in full, on every
/// signed `POST /session` attempt, and that route is unauthenticated and
/// reachable from any page.
///
/// The budget is N hybrid verifies — both halves, `skep_signature::verify`
/// under each key's own row — against the two cheap requests that buy it: one
/// `GET /challenge`, one `POST /session`, neither carrying a credential. At
/// [`MAX_ENROLLED_KEYS`] the bill is order 2 ms (sixteen tag-1 verifies at
/// the design record's ~134 µs each), commensurate with the frame parse
/// beside it; at the record's own [`skep_identity::MAX_RECORD_BYTES`] bound —
/// 128 KiB, 32 tag-1 key entries or 68 tag-3 — it is order 4–5 ms, which the
/// worker pool would rather not absorb per unauthenticated request. "No
/// cutoff, ever" (AUTH-4.33) is what makes the cap belong HERE, at the
/// deposit, rather than at the verification.
///
/// The pre-claim window is the reachable one and the exposure is
/// permanent: slot (7) is arm-blind, so a bare genesis plant on a claimed
/// board dies there, while anything seeded before the claim can be retired
/// only by an anchor session of that account — whose keys the planter
/// chose.
const MAX_GENESIS_KEYS: usize = MAX_ENROLLED_KEYS;

/// The most keys slot (4) decodes: ONE past the cap slot (5) applies. A
/// record past that cap is refused whatever the rest decode to, so every
/// decode beyond it is work an over-cap frame buys and never spends — up to
/// 68 tag-3 (32 tag-1) all-halves decodes at the record's own upstream
/// [`skep_identity::MAX_RECORD_BYTES`] of 128 KiB, an Ed25519 point
/// decompression and a lattice-key decode each, held under
/// `credential_lock.write()` AND the serialization lock, bought by a
/// 150-byte deposit naming one pre-inserted atom.
///
/// The two caps are equal by definition today. If they ever diverge this
/// must be the LARGER, or an over-cap record on the larger arm re-opens the
/// same bill.
const MAX_DECODED_KEYS: usize = MAX_GENESIS_KEYS + 1;

// ── op_shape_refusal — slots (1)–(2), lock-free (AUTH-3.4–3.6) ───────────

/// Slots (1) `emit_not_make_link` and (2) `resolved_from`, evaluated (1)
/// then (2), reading the op's OWN slots and nothing else — evaluated
/// beside `deposits_credential_link` and AHEAD of `credential_lock.write()`
/// (AUTH-3.5): a refusal here never takes the write lock. Behind (2), the
/// credential deposit's `replaces` FENCE (signed ops; BW-04, owner-ruled
/// 2026-09-29): a credential-typed `make_link` carrying a `replaces` member
/// is `replaces_not_credential` — the record's `replaces` row is EMPTY BY
/// KIND, so the member names a state no credential record replaces and the
/// record's `sig`, made over the empty row, could cover no link it would
/// deposit. A shape fact of the frame, so it sits here with the other two.
///
/// PRECONDITION: `deposits_credential_link(op)` holds — the credential
/// sequence's route, this function's one caller (`server/op.rs`'s
/// `credential_sequence`). The arms read no type slot: every `emit` and
/// every `edit_link` is refused unconditionally, which is true of a
/// CREDENTIAL-typed one alone, so on any other op this answers a refusal no
/// rule gives it. The debug assert is what makes the premise loud where a
/// test can see it; the route is the one place it is discharged.
pub(crate) fn op_shape_refusal(op: &Op) -> Option<CredentialRefusal> {
    debug_assert!(
        deposits_credential_link(op),
        "op_shape_refusal's precondition: a credential-typed deposit, the credential route's"
    );
    match op {
        // (1) — every credential-typed emit, unconditionally: M7's dedup
        // could hand a phantom ack for an act key_set never shows.
        Op::Emit { .. } => Some(CredentialRefusal::EmitNotMakeLink),
        // (2) — a credential deposit whose from OR to entity slot is a
        // Resolve, either of them, regardless of emptiness; then the
        // `replaces` fence (BW-04) on the member's presence alone.
        Op::MakeLink { from, to, replaces, .. } => {
            if matches!(from, SlotArg::Resolve(_)) || matches!(to, SlotArg::Resolve(_)) {
                Some(CredentialRefusal::ResolvedFrom)
            } else if replaces.is_some() {
                Some(CredentialRefusal::ReplacesNotCredential)
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

// ── claim_residue_refusal — the claim's own admission (PUB-6.63; RES-24) ──

/// PUB-6.63 (PUB-6.35 clause (b); PUB round 2, lane 4.2 — F2): THE CLAIM
/// REFUSES OVER RESIDUE. The claim — the ceremony's step 5 — is admitted
/// ONLY where the TOP-LEVEL account space holds EXACTLY ONE principal minted
/// by `delegate` ABOVE THE GENESIS FLOOR — the one this ceremony's own
/// `delegate` minted — and is refused `claim_residue` otherwise, from every
/// hand, bare and signed alike: unrefused, a second hand's keyed partial
/// (register cell I10.b) or the operator's own abandoned partial beside its
/// lost-state retry (I11.d) survives the claim as a keyed top-level
/// principal no act removes (PUB-1.44, PUB-1.45), inside every ANY-PRINCIPAL
/// grant the board ever issues. The cure is the one PUB-6.63 pins, verbatim
/// in the face: "this board carries pre-claim residue — re-genesis before
/// claiming."
///
/// THE INPUT is the daemon's own top-level frontier, read AT the claim off
/// the snapshot the write guard pinned — the same fact `next_account_prefix`
/// answers principal-free (PUB-6.52), so a door can face the residue ahead
/// of the ceremony's step 1 from the same read. CARDINALITY, never
/// provenance (provenance is AUTH's: the latch, AUTH-3.82/3.83, is what makes
/// the one counted principal claimable by its minter alone). "Top-level" is
/// the claimant's own tier — the node its account was delegated under
/// (`parent`, the same M1 step the fold's delegator test takes; a claim
/// reaching this producer has already passed `claimant_not_top_level`).
///
/// THE FLOOR is what the daemon's own genesis writes seeded, computed from
/// [`World::genesis`] and never hard-coded: every account genesis mints under
/// that node stands BELOW the count. Genesis seeds none today, so the floor
/// is zero and the two frontiers coincide — counted from the live frontier
/// alone, a board whose genesis seeded a top-level account would refuse
/// every honest claim and its named cure would re-seed it (PUB-6.63's own
/// cycle warning).
///
/// Placed at the claim's own admission in the pre-claim path — slot (8)'s
/// CLAIM arm in [`precheck`], behind the fold's verdict (an `already_claimed`
/// or `claimant_keyless` claim never reaches this) and ahead of the claim's
/// `make_link` ever reaching the store — so a refused claim commits nothing
/// and the board stays unclaimed. The honest single-principal ceremony is
/// exactly the admitted case: one top-level principal above the floor.
/// Fail-CLOSED on the two unreachable shapes (an account with no parent, a
/// node with no frontier): a claim whose count cannot be read is refused,
/// which is the spec's direction ("admitted ONLY where … and refused
/// otherwise").
///
/// `world` MUST be the snapshot taken under the write guard for this
/// request — the frontier is read AT the claim, off the snapshot that guard
/// pinned — and the guard argument is that contract's cheap half, as it is
/// on every other producer in this family.
fn claim_residue_refusal(
    _lock: &LockWrite<'_>,
    world: &World,
    account: &Address,
) -> Option<CredentialRefusal> {
    let Some(node) = parent(account) else {
        return Some(CredentialRefusal::ClaimResidue);
    };
    let Some(count) = accounts_under(world, &node) else {
        return Some(CredentialRefusal::ClaimResidue);
    };
    let floor = accounts_under(&World::genesis(), &node).unwrap_or_else(|| Nat::from(0u32));
    if count == floor + Nat::from(1u32) {
        None
    } else {
        Some(CredentialRefusal::ClaimResidue)
    }
}

/// The number of accounts minted under `node`, read off the frontier exactly
/// as `next_account_prefix` publishes it (PUB-6.52): the next delegable
/// prefix under a node is `node·0·(n+1)`, so its ordinal less one is `n`.
/// `None` where the node anchors no account chain — not a registered node,
/// or a frontier whose ordinal is not the positive number that arithmetic
/// needs.
///
/// The ordinal is ≥ 1 twice over: `next_account_prefix` publishes
/// `node·0·(n+1)`, and T4 refuses a trailing zero on every `Address`, which
/// is what `ordinal` reads. CHECKED rather than trusted, because `Nat` is a
/// `BigUint` and its subtraction PANICS on underflow — and this runs under
/// `credential_lock.write()` AND the write-serialization lock, so a zero
/// here would be a 500 on the claim path where a refusal is available.
/// Fail-CLOSED, joining the two unreachable shapes
/// [`claim_residue_refusal`] already refuses: a claim whose count cannot be
/// read is refused.
fn accounts_under(world: &World, node: &Address) -> Option<Nat> {
    let next = world.m3().next_account_prefix(node)?;
    let ord = ordinal(next.tumbler());
    (ord > &Nat::from(0u32)).then(|| ord.clone() - Nat::from(1u32))
}

// ── precheck — slots (3)–(8), under the write lock (AUTH-3.15–3.19) ──────

/// The owned span form of one would-be deposit, built from the frame
/// VERBATIM (AUTH-3.17): `home` verbatim, `from`/`to`/`ty` as
/// address-form spans via M7's `enc`, in endset order. The fields are
/// private and [`DepositSpans::of`] is the one constructor, so the spans the
/// precheck classifies are always the frame's own, read through
/// [`addr_spans`] — the spelling [`super::deposits_credential_link`]
/// classified the same frame by.
pub(crate) struct DepositSpans {
    home: Address,
    from: Vec<Span>,
    to: Vec<Span>,
    ty: Vec<Span>,
}

impl DepositSpans {
    /// `Some` only for a `MakeLink` whose three slots are all address-form
    /// — the one op that reaches deposit construction (`Emit` dies at slot
    /// (1), `EditLink` at slot (2), a `Nullify` is `nullify_refusal`'s).
    pub fn of(op: &Op) -> Option<DepositSpans> {
        let Op::MakeLink { home, from, to, ty, .. } = op else { return None };
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

/// What the precheck established about the RECORD'S OWN `sig` (signed ops,
/// 2a) — the one thing it hands forward, for the change feed's row: whether
/// the record grade's check ran and VERIFIED the `sig` (the claimed arm's
/// slot (7)), so the deposit's row testifies its entry signed by its
/// record and serves no `key` (D12); or whether the record went unjudged
/// (the pre-claim arm, A5: at or below the claim nothing is signed, so the
/// ceremony's own record goes unjudged, `sig` or not, and its row serves its
/// `key`). Never the previewed effect (below).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordSig {
    /// The record's `sig` verified at [`record_grade_check`].
    Verified,
    /// No record grade ran: at or below the claim.
    Unjudged,
}

/// The precheck's answer: the refusal, or what it established about the
/// record's `sig` ([`RecordSig`]). The previewed effect is deliberately NOT
/// returned — the engine's fold hook re-derives it from the same deposit at
/// the commit itself (`World::apply`, AUTH-2.80), so handing it forward would
/// be a second path to one state change, and a signature that offers it
/// invites exactly that.
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
///
/// THE ACTOR is narrowed to what the session's OPENING fixed (AUTH-3.16): the
/// key that established it and, beside it, the scope it declared (AUTH-4.39;
/// RES-63) — still NO principal, so the forbidden ω check stays unwritable
/// here. `scope` is read at the head of slot (6) and nowhere else.
///
/// `seat` IS AUTH-3.21's SEAT CARVE'S ONE INPUT (AUTH-3.15; RES-195): the
/// blocked-prefix list header's SECOND field, the board's binding-writing
/// account AS ISSUED — the header the handshake compares at step 4b — read
/// at slot (6) beside the claimant, by [`forked_seat`] alone. And
/// `allow_preview_keys` IS THE SETTING SLOT (4) READS (AUTH-1.44; the
/// `preview_key` refusal, AUTH-3.56; AUTH-3.15 as RES-206 landed it) — AND
/// NOTHING ELSE: the whole of [`crate::auth::AuthConfig`] is deliberately out of
/// reach — no configured origin, the local-trust flag, list entry or node
/// prefix can be read from here, because none of them is an argument — and
/// no address, content, cone, document or role rides in on either one.
// Eight arguments, deliberately: each is ONE declared collaborator (AUTH-3.15,
// AUTH-3.16's narrowing), and bundling them would put a struct between the
// caller and the list this doc names — the same call `handshake` makes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn precheck(
    lock: &LockWrite<'_>,
    world: &World,
    identity: &IdentityState,
    dep: &DepositSpans,
    signer: Option<&Fingerprint>,
    scope: Scope,
    seat: Option<&Address>,
    allow_preview_keys: bool,
) -> Result<RecordSig, CredentialRefusal> {
    // THE SYSTEM ACCOUNT TAKES NO CREDENTIAL DEPOSIT (as7-F2; SO-I2 (g)(iv),
    // SO-I4 (c)) — AHEAD of the fold's verdict and on both arms of the
    // board state, so it is the first thing said of such a deposit (P13) and
    // reachable from the wire: behind slot (3) the fold's own home pin would
    // answer it `not_genesis_registry` or `not_doc_one` first, and the
    // claimed arm's record grade and the pre-claim gate's genesis arm would
    // be reached by no wire sequence.
    if names_system_account(world, dep) {
        return Err(CredentialRefusal::SystemAccountKeyless);
    }
    // (3) — the classify preview's verdict (AUTH-2.57): the fold's own
    // order — kind, home account, publication, the per-kind arm.
    let verdict = identity.classify(&IDENTITY_TYPES, world, &dep.deposit());
    let effect = match verdict {
        Verdict::NotCredential => {
            debug_assert!(false, "classify answered NotCredential on a classified deposit");
            return Ok(RecordSig::Unjudged);
        }
        Verdict::Inert(i) => return Err(CredentialRefusal::Inert(i)),
        Verdict::Honored(e) => e,
    };
    // (4) — TWO tokens in THIS order (AUTH-3.44 as RES-206 landed it), over
    // ONE set of keys: every enrolment record's, `Genesis` INSIDE (the cap's
    // genesis exemption is slot (5)'s and is not inherited here: a
    // genesis-planted key is as much a key), none for a retirement or a
    // claim. Exhaustive, so a new `Effect` decides here whether it carries
    // keys.
    let enrolling: &[Enrolled] = match &effect {
        Effect::Enroll { added, .. } => added,
        Effect::Genesis { keys, .. } => keys,
        Effect::Retire { .. } | Effect::Claim { .. } => &[],
    };
    // FIRST `preview_key`: an enrolment record naming ANY key of the PREVIEW
    // row, tag 3 (`fndsa512-preview-ed25519`), unless the daemon's setting
    // allows it (AUTH-1.44). The test reads each key entry's `alg` and
    // decodes nothing, so a preview key that ALSO fails to decode is told this
    // fault first — the one the same act clears, a key made with a released
    // client (AUTH-3.46). Tag-3 VERIFICATION stays compiled in (the
    // frozen-tag rule) and the fold admits the row as syntax; this refuses
    // ENROLLMENT alone. Unbounded over the record's key entries: a token
    // compare per key entry, and the record is the read's cap's (AUTH-2.43).
    if !allow_preview_keys
        && enrolling.iter().any(|e| e.key.alg() == ALG_FNDSA512_PREVIEW_ED25519)
    {
        return Err(CredentialRefusal::PreviewKey);
    }
    // THEN `undecodable_key`: a valid-hex key ANY half of which does not
    // decode — the Ed25519 half's point AND the post-quantum half (the
    // FN-DSA header byte among that half's checks) — can never sign; the
    // fold accepts syntax, the daemon extends the courtesy. The decodes are
    // the very two `skep_signature::verify` runs before its arithmetic
    // (`skep_signature::key_decodes` calls them), so the courtesy cannot
    // disagree with the verify about what decodes. It is BOUNDED by
    // [`MAX_DECODED_KEYS`] — the discipline [`crate::codec`]'s `room`
    // states, applied to the one slot whose input this module cannot cap.
    //
    // CONSEQUENCE: a record that is BOTH over-cap and carries an
    // undecodable key past [`MAX_DECODED_KEYS`] answers `too_many_enrolled`
    // where the slot order alone would say `undecodable_key`. The boundary
    // is the SCAN's and not slot (5)'s: the scan reaches one key past the
    // cap slot (5) applies, so an undecodable key AT that one-past position
    // is still seen and still answers `undecodable_key`. It is refused
    // either way, permanently, in the same vocabulary and by the same
    // function; what changes is which of two true things it is told.
    if !enrolling.iter().take(MAX_DECODED_KEYS).all(|e| skep_signature::key_decodes(&e.key)) {
        return Err(CredentialRefusal::UndecodableKey);
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
    // (6) — TWO tokens, in THIS order (AUTH-3.44; RES-63). The HEAD is
    // `content_session`: a CONTENT-scoped session deposits no credential —
    // every deposit the dispatch routes here, whatever key opened the
    // session and whether or not the act is an anchor act, so an anchor
    // key's content session is refused HERE and never reaches the gate
    // below. Behind slots (3)–(5): a content session's retry of an act
    // another session committed still answers the head's preview token.
    // The scope's ONE read (AUTH-4.39).
    if scope == Scope::Content {
        return Err(CredentialRefusal::ContentSession);
    }
    // (6) — the anchor gate (AUTH-3.20–3.23): an anchor retirement or a
    // post-genesis anchor-flagged enrollment needs a session an anchor of
    // that account established; a bare session never satisfies it; the
    // record is refused WHOLE. Genesis is exempt (the seeding hand records
    // the initial set, flags included) — EXCEPT AT A HANDOFF (AUTH-3.21),
    // which [`handoff_giver`] tells by address: there the gate reads the
    // set that OPENS the account, the giver's, and only where that set
    // holds an anchor — an anchorless giver's handoff stays device-grade
    // (AUTH-5.16's standing price).
    //
    // THE ACCOUNT WHOSE ANCHORS GRADE THIS ACT, answered from two different
    // places: a retirement's and an enrollment's own account, and — at a
    // handoff — the GIVER, which is never the genesis's subject. "Subject" is
    // deliberately unspent on it: the word is live in two senses in this
    // subsystem — the account whose set is CONSULTED
    // ([`crate::auth::session::key_subject`], AUTH-4.30 (i)) and the account being
    // ACTED ON ([`handoff_giver`]'s own parameter) — and the Genesis arm
    // holds both in one expression, where only the first would be true of
    // this value.
    let anchor_account = match &effect {
        Effect::Retire { account, removed } => {
            let set = identity.key_set(account);
            removed.iter().any(|fp| set.is_anchor(fp)).then(|| account.clone())
        }
        Effect::Enroll { account, added } => {
            added.iter().any(|e| e.anchor).then(|| account.clone())
        }
        Effect::Genesis { account, .. } => handoff_giver(identity, seat, account)
            .filter(|giver| identity.key_set(giver).enrolled().any(|(_, e)| e.anchor)),
        Effect::Claim { .. } => None,
    };
    // THE GRADE OF THE ACT (AUTH-3.20–3.22), read here and nowhere else: the
    // gate's own input, and the record grade's below — an anchor-grade act
    // admits an anchor's `sig` alone.
    let anchor_grade = anchor_account.is_some();
    if let Some(anchor_account) = anchor_account {
        let set = identity.key_set(&anchor_account);
        if !signer.is_some_and(|fp| set.is_anchor(fp)) {
            return Err(CredentialRefusal::AnchorSessionRequired);
        }
    }
    // (7)/(8) — the claim-disjoint board-state slots.
    let claimed = identity.claimant().is_some();
    if claimed {
        // (7) — arm-blind: Genesis is NOT exempt here; a bare genesis
        // plant on a claimed board dies at this slot.
        if signer.is_none() {
            return Err(CredentialRefusal::SignedSessionRequired);
        }
        // (7), THE RECORD GRADE (signed ops, 2a; the design record §4.5 (4)):
        // above the claim, the record's own `sig` — verified at this, its
        // `make_link` (D26), under the set that opens its home, at the grade
        // the act needs; a record carrying none is refused. The kind is the
        // fold's verdict's — the link's type slot as the fold parsed it at
        // slot (3), which is the record-deposit set's answer, that set being
        // the fold's kinds (`record_deposit_kind`'s card) — narrowed to the
        // TWO kinds that carry a record (l7-C3): the fold honors no claim on
        // a claimed board (AUTH I5/I6 — a second claim is `already_claimed`
        // at slot (3)), so the claim arm has no population, and were it ever
        // reached the fold's own verdict is the one true answer — never
        // `attestation_required`, an act a record with no payload cannot
        // take (AUTH-2.48).
        let kind = match &effect {
            Effect::Genesis { .. } | Effect::Enroll { .. } => RecordKind::Enroll,
            Effect::Retire { .. } => RecordKind::Retire,
            Effect::Claim { .. } => return Err(CredentialRefusal::Inert(Inert::AlreadyClaimed)),
        };
        record_grade_check(world, identity, dep, kind, anchor_grade)?;
        Ok(RecordSig::Verified)
    } else {
        // (8) — the pre-claim admission gate's deposit cell, evaluated on
        // the slot-(3) preview: only the ceremony's own deposits pass — and
        // the claim passes only where its OWN admission admits it
        // (PUB-6.63's residue test, [`claim_residue_refusal`]): behind the
        // fold's verdict, ahead of the store, so a refused claim commits
        // nothing and the board stays unclaimed. The ceremony's genesis arm
        // admits no genesis whose subject or home is the system account
        // (as7-F2) — refused ahead of slot (3), above: the one pre-claim
        // plant `claim_residue` cannot count, the account sitting at the
        // genesis floor under `1.1`.
        match &effect {
            Effect::Genesis { .. } => {}
            Effect::Claim { account } => {
                if let Some(r) = claim_residue_refusal(lock, world, account) {
                    return Err(r);
                }
            }
            _ => return Err(CredentialRefusal::ClaimFirst),
        }
        Ok(RecordSig::Unjudged)
    }
}

/// THE SYSTEM ACCOUNT HOLDS NO KEY (PUB-6.65; signed ops, round 7 — as7-F2
/// = reg-S3; SO-I2 (g)(iv); SO-I4 (c)): `true` iff the deposit's SUBJECT —
/// the enrolled principal, the one address the link's `to` slot names (the
/// same read the fold makes of it, [`single_address`]; a claim's `to` is
/// empty and names none) — or the owner of its HOME by ω (a READ of Π, m3)
/// is the system account `1.1.0.1`. Read at the head of [`precheck`], ahead
/// of the fold's verdict and on both arms of the board state, so no key is
/// ever enrolled in that account by any sequence the daemon admits — the
/// claimed board's record grade and the unclaimed board's genesis arm stand
/// behind it. A3's exemption of the head writer's own writes keys on the
/// same account and is untouched: those are no credential deposits.
fn names_system_account(world: &World, dep: &DepositSpans) -> bool {
    let system = system_account();
    single_address(&dep.to).as_ref() == Some(&system)
        || world.m3().effective_owner_prefix(&dep.home) == Some(&system)
}

/// THE RECORD GRADE'S OWN KIND (l7-C3; SO-I7): the two kinds whose record
/// carries a `sig` — ENROLL (a genesis's or a holder's enrolment, both an
/// `Enrollment` record) and RETIRE (a `Fingerprint` record). A claim carries
/// no record (AUTH-2.48) and reaches no claimed board's record grade, so it
/// is UNREPRESENTABLE here rather than asserted away: a `Claim` arm, and the
/// `attestation_required` a release build once answered one, cannot be
/// written. The disavowal's and the registry's kinds join at their RESes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordKind {
    Enroll,
    Retire,
}

/// THE RECORD GRADE'S CHECK (signed ops, 2a; the design record §4.5 (4) and
/// its table clauses (a)–(c); D26; AUTH-2.94 — a write-path check, never a
/// fold input): ABOVE THE CLAIM ON A CLAIMED BOARD, a credential record the
/// fold would honor carries its own `sig`, verified HERE, at the deposit's
/// `make_link` — the position the fold honors and the record's `sig` covers,
/// its atom's `insert` having taken no entry check (D26). In order:
///
/// 1. THE RECORD VALUE — the atom's bytes off the link's `from`, the one
///    pinned read ([`record_bytes`]), parsed ([`parse_record_value`]) by the
///    KIND the fold's verdict names for the link's type — the record-deposit
///    set's answer, that set being the fold's kinds, narrowed to the two that
///    carry a record ([`RecordKind`]; a claim is unrepresentable here): the
///    entries and the `sig` as it stands. The fold read and parsed these same
///    bytes at slot (3), so a failure here is unreachable and is answered
///    fail-closed, as a record no `sig` can be read off.
/// 2. NO `sig` → `attestation_required` (§4.5 (4): "REFUSE A BODY THAT
///    CARRIES NO `sig` AT ALL") — a FENCE with no population on a conforming
///    daemon since round 7 (bu7-E1 ARM (a)): a sig-less record-kind atom is
///    refused at its `insert`, `record_sig_required`, PERMANENT, and lands
///    nowhere (`policy/attestation.rs`'s step 2), so the only atom this
///    reaches was deposited past that gate — below the claim, or past the
///    check by the operator's hand; the class REORDER, the act that exists
///    being a new record composed with its `sig`, inserted and linked.
///
/// Steps 3 to 6 are [`verify_record_sig`], the trial the registry arm calls
/// too (`policy/registry.rs`), so the two grades verify one way:
///
/// 3. THE BLOB — the `sig` is the hybrid blob in hex, no `alg` beside it,
///    parsed by the one parse both doors share ([`HybridSig::parse`],
///    case-free) into a WIDTH-VALIDATED blob that NAMES NO ROW (l7-C3; SO-I6
///    (i)): row identity comes from each candidate key alone at step 6, and
///    where two rows share a width both rows' keys enter the trial; hex of
///    no row's width is `attestation_invalid:malformed`, PERMANENT.
/// 4. THE FRAME — the `record` grammar over the link and the atom
///    ([`entry::compose_record`]): `H.1`'s pair (none →
///    `board_unavailable`), the HOME's account (ω over the home, the fold's
///    own H) and the home, the link's type and target addresses read off the
///    deposit's slots as a mirror reads them off the stored link, the
///    `replaces` and lineage rows EMPTY, and the sig-less projection
///    `canonical_record(entries, None)`. The home's account and the type
///    address are both read off what slot (3) established — the fold's
///    classify found the home an owner, and its `kind_of` read the type slot
///    as the one span `single_address` reads — so an absence is a premise
///    broken, answered fail-closed and asserted.
/// 5. THE CANDIDATES (clause (a), AT WHICH STATE clause (b)): the enrolled
///    keys of THE SET THAT OPENS THE HOME'S ACCOUNT — [`opening_account`]'s
///    walk, the one `key_subject` takes: the home's own set where it is not
///    empty, else the nearest keyed account above (a hire's genesis is homed
///    in `X.1`'s doc 1, and `X.1` holds no set of its own) — as of THIS BASE,
///    the snapshot under the write guard, the deposit's own effects not yet
///    posted (a rotation's retire-old is signed by the key it retires);
///    FILTERED TO THE GRADE THE ACT NEEDS (AUTH-3.20–3.22): where the act is
///    anchor-grade — slot (6)'s own reading, `anchor_grade` — the ANCHORS
///    among them alone; and of those, the keys whose row's blob is the
///    blob's width. None → `attestation_invalid:not_enrolled_at_position`,
///    PERMANENT.
/// 6. THE TRIAL — each candidate, the frame under ITS row's token as `alg`,
///    both halves ([`skep_signature::verify`]); any verifying admits, none →
///    `attestation_invalid:signature`, PERMANENT.
///
/// The check reads the FOLD's key table (BW-02, owner-ruled 2026-09-29: no
/// second table at the daemon), on the equality this very check establishes
/// above the claim: every record the fold honors there passed it at this
/// daemon's own write path, so the fold's table and a verifier's filtered
/// table hold one record set. A record LIFTED into a stranger's doc 1 fails
/// at step 6: the frame names THAT home and its account, and the `sig` was
/// made over another's. At or below the claim nothing runs here (A5): the
/// ceremony's own records go unjudged, `sig` or not, and this function is
/// reached only from the claimed arm.
///
/// `world` and `identity` MUST be the pair taken under the write guard for
/// this request, as `precheck`'s are; `dep` the deposit slot (3) classified
/// `Honored`, and `kind` its kind.
fn record_grade_check(
    world: &World,
    identity: &IdentityState,
    dep: &DepositSpans,
    kind: RecordKind,
    anchor_grade: bool,
) -> Result<(), CredentialRefusal> {
    let invalid = CredentialRefusal::AttestationInvalid;
    // 1 — the record value, by the kind's parse.
    let value = match kind {
        RecordKind::Enroll => record_value::<Enrollment>(world, dep),
        RecordKind::Retire => record_value::<Fingerprint>(world, dep),
    };
    let Some((canonical, sig)) = value else {
        debug_assert!(
            false,
            "the record grade read no record value for a {kind:?} deposit slot (3) honored: an \
             enrollment's or retirement's bytes the fold just parsed cannot fail to parse here"
        );
        return Err(CredentialRefusal::AttestationRequired);
    };
    // 2 — no `sig` at all: the fence for an atom deposited past the insert's
    // own gate, with no population on a conforming daemon (bu7-E1).
    let Some(sig) = sig else {
        return Err(CredentialRefusal::AttestationRequired);
    };
    // 3–6 — the trial, shared with the registry arm. The home's account is
    // ω's answer, the fold's own H (slot (3) found one, so this is `Some`),
    // borrowed off the snapshot as every read here is; the slots are read as
    // a mirror reads a stored link's: one address each, the `to` slot empty
    // at a targetless kind. The type slot is the one `kind_of` read at
    // slot (3) — one span, a type's own subtree — so it reads as an address:
    // both premises of slot (3)'s verdict, answered fail-closed and asserted,
    // as step 1's is.
    let Some(home_account) = world.m3().effective_owner_prefix(&dep.home) else {
        debug_assert!(false, "slot (3) honored a deposit whose home has no owner");
        return Err(invalid(AttestFault::NotEnrolledAtPosition));
    };
    let Some(ty) = single_address(&dep.ty) else {
        debug_assert!(false, "slot (3) classified a type slot single_address cannot read");
        return Err(invalid(AttestFault::Signature));
    };
    let to = single_address(&dep.to);
    verify_record_sig(
        world,
        identity,
        RecordTrial {
            home: &dep.home,
            home_account,
            ty: &ty,
            to: to.as_slice(),
            canonical: canonical.as_bytes(),
            sig: &sig,
            anchor_grade,
        },
    )
    .map_err(invalid)
}

/// THE RECORD GRADE'S TRIAL, its inputs by name — what [`verify_record_sig`]
/// takes: the deposit's home and the home's account (ω over the home, the
/// frame's `account`), the link's type address and its target as stored
/// (none at a targetless kind), the SIG-LESS CANONICAL PROJECTION of the
/// record (the frame's body-bytes row), the record's `sig` as found, and
/// whether the act is ANCHOR-GRADE (AUTH-3.20–3.22: the credential arm's
/// slot (6) reading; FALSE for a registry record, no rule naming an anchor
/// grade for one). By field, as [`RecordRows`](skep_identity::RecordRows)
/// takes the frame's rows: the two arms that compose one name each input.
pub(super) struct RecordTrial<'a> {
    pub home: &'a Address,
    pub home_account: &'a Address,
    pub ty: &'a Address,
    pub to: &'a [Address],
    pub canonical: &'a [u8],
    pub sig: &'a str,
    pub anchor_grade: bool,
}

/// THE TRIAL — steps 3 to 6 of [`record_grade_check`], the one function the
/// credential arm and the registry arm (`policy/registry.rs`; the record
/// grade for registry records, 2b) both call, so the two grades verify one
/// way: the blob, the frame, the candidates, the trial. Each fault is the
/// `attestation_invalid` cause the caller joins to its own family's code.
pub(super) fn verify_record_sig(
    world: &World,
    identity: &IdentityState,
    trial: RecordTrial<'_>,
) -> Result<(), AttestFault> {
    // 3 — the blob, width-validated, naming no row (l7-C3).
    let blob = HybridSig::parse(trial.sig).ok_or(AttestFault::Malformed)?;
    let blob = blob.as_bytes();
    // 4 — the frame, every member but `alg`: the `record` grammar over the
    // link and the atom, `H.1`'s pair (none → `board_unavailable`), the
    // home's account and the home, the type and target as stored, the
    // `replaces` and lineage rows EMPTY, the sig-less projection.
    let Some(frame) = entry::compose_record(
        world,
        trial.home_account,
        trial.home,
        trial.ty,
        trial.to,
        trial.canonical,
    ) else {
        return Err(AttestFault::BoardUnavailable);
    };
    // 5 — the candidates: the set that opens the home's account, at the
    // grade the act needs, of the blob's row.
    let opening = opening_account(identity, trial.home_account);
    let candidates: Vec<&PublicKey> = identity
        .key_set(&opening)
        .enrolled()
        .filter(|(_, e)| !trial.anchor_grade || e.anchor)
        .map(|(_, e)| &e.key)
        .filter(|key| key.sig_alg_row().sig_len() == blob.len())
        .collect();
    if candidates.is_empty() {
        return Err(AttestFault::NotEnrolledAtPosition);
    }
    // 6 — the trial, the frame under each candidate's own token.
    if candidates.iter().any(|key| {
        let bytes = frame.to_bytes(key.alg());
        skep_signature::verify(key.sig_alg_row().tag, key, &bytes, blob).is_ok()
    }) {
        Ok(())
    } else {
        Err(AttestFault::Signature)
    }
}

/// The record value a deposit's atom carries, for the record grade: the
/// sig-less canonical projection and the `sig` as it stands — read by the one
/// pinned read over the world as the fold's ctx (the engine's `FoldCtx for
/// World`) and parsed by the kind `T` names, as the fold reads and parses it
/// (`None` where either refuses, which the fold's own verdict at slot (3)
/// makes unreachable).
fn record_value<T: RecordEntry>(world: &World, dep: &DepositSpans) -> Option<(String, Option<String>)> {
    let bytes = record_bytes(world, &dep.home, &dep.from).ok()?;
    let value = parse_record_value::<T>(&bytes).ok()?;
    Some((canonical_record(&value.entries, None), value.sig))
}

/// AUTH-3.21's ADDRESS TEST — what slot (6) tells of one previewed
/// `Honored(Genesis)` BY ADDRESS, the one fact the precheck holds (ONE
/// AUTHORITY, AUTH-2.109): `Some(S)` iff the genesis is a HANDOFF, `S` the
/// GIVER — the account whose set opens `subject` and so grades the act; `None`
/// for every genesis the gate is silent on. No document is read and no cone:
/// `has_documents` stays MINT-FIRST's.
///
/// The rule's one sentence (RES-175): *a genesis is measured at the nearest
/// keyed account above its address: beneath that account's agent space it is
/// a HIRE's, beneath an agent it is a SPAWN's, into a direct child of a forked
/// lineage's SEAT it is an ADMISSION's — each device-grade — anywhere else
/// beneath a party's keys it is that party's HANDOFF, and a top-level
/// account's own genesis enters no cone.* Arm by arm:
///
/// * `S` is the walk's TERMINUS ([`keyed_above`] — AUTH-4.30 (i)'s walk, the
///   one `key_subject` takes), read ONCE and at no keyed account further up
///   the chain (RES-172); where no keyed account stands above `subject` the
///   genesis lies in NO cone — a bootstrap-tier account's own, the invite's,
///   an org door's top-level mint, a never-keyed chain's;
/// * a HIRE (AUTH-5.58 step 4) lands beneath `S`'s agent space — a child of
///   its FIRST SUB-ACCOUNT `inc(S, 1)`, the rule's own words, and never a
///   deeper address: beneath an unseeded agent's slot nothing is a hire;
/// * a SPAWN (AUTH-5.63) lands beneath an AGENT: `S` itself stands at
///   `inc(inc(P, 1), n)` beneath ITS OWN nearest keyed ancestor `P`, and a
///   keyed account at any other position is no agent — so a handed-off
///   account standing elsewhere never reads as one. `P` is read to place `S`,
///   never to grade the act;
/// * an ADMISSION (RES-175's seat carve) lands in a DIRECT CHILD of the
///   board's binding-writing account where that account is not the claimant
///   ([`forked_seat`]) — the seat's own FIRST SUB-ACCOUNT, `inc(seat, 1)`
///   itself, is no admission and stays a handoff;
/// * ANY OTHER genesis into a by-reference descendant of `S` — `S`'s own
///   first sub-account `inc(S, 1)`, the agents' home, included; `S` a
///   person's account, an org root's or a node account's alike, the address
///   read and never the role — is `S`'s HANDOFF.
///
/// The caller grades a handoff at `S`'s set: anchor-grade wherever that set
/// holds an anchor, device-grade where it holds none.
fn handoff_giver(
    identity: &IdentityState,
    seat: Option<&Address>,
    subject: &Address,
) -> Option<Address> {
    let giver = keyed_above(identity, subject)?;
    let subject_parent = parent(subject);
    let first_sub_account = |of: &Address| checked_inc(of, 1).ok();
    // The HIRE's: a child of the giver's first sub-account, its agent space.
    if subject_parent == first_sub_account(&giver) {
        return None;
    }
    // The SPAWN's: the giver is itself an agent.
    let giver_is_agent = keyed_above(identity, &giver)
        .is_some_and(|holder| parent(&giver) == first_sub_account(&holder));
    if giver_is_agent {
        return None;
    }
    // The ADMISSION's: a direct child of a forked lineage's seat, the seat's
    // own first sub-account apart.
    if let Some(seat) = forked_seat(seat, identity) {
        if subject_parent.as_ref() == Some(seat)
            && first_sub_account(seat).as_ref() != Some(subject)
        {
            return None;
        }
    }
    Some(giver)
}

/// THE SEAT CARVE'S COMPARISON (AUTH-3.15, AUTH-3.21; RES-175, RES-195): the
/// SEAT of a forked lineage — the list header's SECOND field, the board's
/// binding-writing account (AUTH-4.36 step 4b; REG-3.52), where it is NOT the
/// claimant. `None` — the carve SILENT — where the header omits the field
/// (the claimant is then the binding-writing account) or names the claimant:
/// on every unforked lineage the two are one account, so the carve reaches no
/// notebook and no unforked org board.
///
/// `seat` is the field AS ISSUED ([`crate::auth::BlockedPrefixes::header`]), never
/// as the install resolved its comparand (b): that one is live only where the
/// operator is off-board, which is the BLOCK's question and not the carve's.
/// It arrives as an argument rather than as a config this reads for itself,
/// so the whole of [`crate::auth::AuthConfig`] — every configured origin,
/// flag, list entry and the node prefix — is out of reach of this gate by
/// construction. Compared against `identity.claimant()`: the daemon derives
/// nothing and reads no record for it.
///
/// SILENT on an UNCLAIMED board too: there is no claimant for the field to
/// differ from and no lineage to have forked. The rule does not speak to the
/// cell, and the carve only ever WIDENS — so where its comparison has no
/// referent the gate keeps its grade.
fn forked_seat<'a>(seat: Option<&'a Address>, identity: &IdentityState) -> Option<&'a Address> {
    let claimant = identity.claimant()?;
    let seat = seat?;
    (claimant != seat).then_some(seat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::policy::addr_of;

    /// The seat carve is SILENT wherever its comparison has no referent: with
    /// no header field, and — the cell the rule does not speak to — on an
    /// UNCLAIMED board, whose header can differ from no claimant. The claimed
    /// cells (the field naming the claimant; naming another account) are
    /// `auth_wire`'s, over the wire.
    #[test]
    fn the_seat_carve_is_silent_with_no_header_and_on_an_unclaimed_board() {
        let unclaimed = IdentityState::genesis();
        assert_eq!(forked_seat(None, &unclaimed), None, "the header omits the field");
        let seat = addr_of(&[1, 0, 7]);
        assert_eq!(
            forked_seat(Some(&seat), &unclaimed),
            None,
            "no claimant for the field to differ from"
        );
    }

    /// `op_shape_refusal`'s PRECONDITION IS MONITORED: its arms read no type
    /// slot, so on an op the credential route never sends it — a GRANT-typed
    /// `emit`, which its arm would refuse unconditionally — it would answer a
    /// refusal no rule gives, and a debug build stops instead. The route is
    /// the one place the premise is discharged; this pins that it is loud.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "op_shape_refusal's precondition")]
    fn op_shape_refusal_stops_on_an_op_the_credential_route_never_sends() {
        let doc = addr_of(&[1, 0, 1, 0, 1]);
        let grant_type = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 90]);
        let grant_emit = Op::Emit {
            home: doc.clone(),
            ty: skep_links::enc([&grant_type]),
            from: doc,
            to: Vec::new(),
        };
        let _ = op_shape_refusal(&grant_emit);
    }

    /// A CLAIMED BOARD WITH NO `H.1` ANSWERS A JUDGED RECORD
    /// `attestation_invalid:board_unavailable` — REORDER, the board's state and
    /// never the record's (the record grade's step 4: `compose_record`'s one
    /// refusal, `board_term`'s states). The ceremony is run through M10 alone,
    /// so no head writer runs: the world is claimed and holds no `H.1`, and a
    /// retirement whose record carries a well-formed `sig` passes slots (3)–(6)
    /// and meets the record grade with no board term to compose over. The wire
    /// reaches this only through a first head the driver refused, which no
    /// suite can produce.
    #[test]
    fn a_claimed_board_with_no_h1_answers_the_record_grade_board_unavailable() {
        use serde_json::json;
        use skep_febe::{Codec, OperationSurface, Response};
        use skep_identity::encode_enroll;
        use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
        use skep_namespace::PrincipalId;
        use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

        use skep_engine::types::{t_claim, t_enroll, t_retire};
        use skep_identity::HasIdentity;

        use crate::auth::CredentialLock;
        use crate::codec::JsonCodec;
        use crate::write_path::board_term;

        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let febe = OperationSurface::new(Box::new(engine.stores()));
        let ty = |t: &Address| t.tumbler().to_string();
        let key = |n: u8| {
            let signer = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[n; 32]).expect("tag 1");
            signer.public_key().clone()
        };
        let (anchor, device) = (key(1), key(2));
        let exec = |sid, frame: serde_json::Value| -> String {
            let req = JsonCodec
                .parse(frame.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail));
            match febe.execute(sid, req) {
                Response::AckAddr { addr, .. } => addr.tumbler().to_string(),
                other => panic!("{frame}: {}", String::from_utf8_lossy(&JsonCodec.marshal(&other))),
            }
        };
        // THE CEREMONY, through M10: the account, its doc 1, the genesis, the claim.
        let delegate = json!({"op": "delegate", "new_prefix": "1.0.1", "new_id": 900});
        exec(febe.bootstrap_session(), delegate);
        let sid = febe.open_session(PrincipalId(900));
        let doc1 = exec(sid, json!({"op": "create_new_document", "account": "1.0.1"}));
        let atom = |ordinal: u64, text: String, t: &Address| {
            json!({"op": "insert", "doc": doc1,
                   "at": {"subspace": "1", "ordinal": ordinal.to_string()},
                   "values": [{"atom": text}], "deposit": ty(t)})
        };
        let link = |from: &str, to: &[&str], t: &Address| {
            json!({"op": "make_link", "home": doc1, "from": {"addrs": [from]},
                   "to": {"addrs": to}, "ty": {"addrs": [ty(t)]}})
        };
        let genesis = encode_enroll(&[
            Enrollment::new(anchor, true, None).expect("no label"),
            Enrollment::new(device.clone(), false, None).expect("no label"),
        ]);
        let genesis_atom = exec(sid, atom(1, genesis, t_enroll()));
        exec(sid, link(&genesis_atom, &["1.0.1"], t_enroll()));
        exec(sid, link("1.0.1", &[], t_claim()));
        // A retirement of the device key, its record carrying a tag-1-width `sig`.
        let retire = canonical_record(&[Fingerprint::of(&device)], Some(&"ab".repeat(3373)));
        let retire_atom = exec(sid, atom(2, retire, t_retire()));
        let op = JsonCodec
            .parse(link(&retire_atom, &["1.0.1"], t_retire()).to_string().as_bytes())
            .unwrap_or_else(|e| panic!("{:?}", e.detail))
            .op;
        let dep = DepositSpans::of(&op).expect("an address-form make_link");

        let snap = engine.kernel().snapshot();
        let world = snap.world();
        assert!(board_term(world).is_none(), "the premise: no head writer ran, so no H.1");
        // The slice the World carries, stepped at each of the ceremony's
        // deposits by the engine's own fold hook.
        let identity = world.identity();
        assert!(identity.claimant().is_some(), "the premise: the ceremony claimed the board");
        let lock = CredentialLock::new();
        assert_eq!(
            precheck(
                &lock.write(),
                world,
                identity,
                &dep,
                Some(&Fingerprint::of(&device)),
                Scope::Full,
                None,
                false
            ),
            Err(CredentialRefusal::AttestationInvalid(AttestFault::BoardUnavailable)),
            "no board term to compose the record frame over: the state's REORDER cause"
        );
    }
}
