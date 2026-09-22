//! Verdicts, effects, and the inert vocabulary — AUTH-2.51–2.55.

use skep_address::Address;

use crate::key::Fingerprint;
use crate::keyset::Enrolled;
use crate::payload::PayloadError;

/// AUTH-2.51 — a deposit's fold verdict. `classify` is the verdict `step`
/// would reach without applying it (AUTH-2.57) — the daemon's precheck and
/// the mirror's oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not a credential deposit at all (AUTH-2.77): nullifies, `assert_sup`
    /// claims, retraction/supersession tuples, unrecognized types — state
    /// unchanged. The fold reads DEPOSITS, the audit view: a nullified
    /// credential link still counts (AUTH-2.78, I8 AUTH-2.103).
    NotCredential,
    /// A credential-shaped deposit the fold refuses; the table is unchanged
    /// and the reason is the token (AUTH-2.54).
    Inert(Inert),
    /// An honored deposit; the carried effect is what `apply` posts.
    Honored(Effect),
}

/// AUTH-2.51/AUTH-2.52 — a faithful description of the change `apply` posts.
/// `account` names the account each arm concerns, which is not the same fact
/// on all four: on `Genesis`/`Enroll`/`Retire` it is the account whose KEY
/// SET the post amends; on `Claim` it is the CLAIMANT, and that arm amends
/// no set — it posts `claimant`. `apply` reads the effect and DECIDES
/// NOTHING (AUTH-2.53).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// The genesis arm's post (AUTH-2.70): the account AND the keys the step
    /// seeds it with, in the same `Enrolled` shape `Enroll` uses — never the
    /// bare fingerprint, because the apply constructs the map's values
    /// (AUTH-2.52). Fires at most once per account (I5, AUTH-2.100).
    Genesis {
        /// The seeded account.
        account: Address,
        /// The seeding keys, flags as the entries carry them.
        keys: Vec<Enrolled>,
    },
    /// The holder-enrollment post (AUTH-2.69): each ADDED key with the flag
    /// it enters under.
    Enroll {
        /// The enrolling account.
        account: Address,
        /// The keys actually added (`∉ enrolled ∧ ∉ retired`).
        added: Vec<Enrolled>,
    },
    /// The retirement post (AUTH-2.74): fingerprints only.
    Retire {
        /// The retiring account.
        account: Address,
        /// The fingerprints removed (`F ∩ enrolled`).
        removed: Vec<Fingerprint>,
    },
    /// The claim post (AUTH-2.67 item 6): `claimant = Some(account)`; at
    /// most one ever (I6, AUTH-2.101).
    Claim {
        /// The claiming account.
        account: Address,
    },
}

/// AUTH-2.54 — the inert vocabulary. A VERDICT and never an `Err` — it
/// reaches no `Result` in this crate — so it is not a `std::error::Error`,
/// and deliberately not `Display` either. A refusal's wire detail is
/// [`token`]'s string on every arm but [`MalformedPayload`], whose detail is
/// the JOIN; a `Display` writing `token()` alone would answer
/// `malformed_payload` where the detail is `malformed_payload:bad_record` —
/// half a wire detail, from the one trait a consumer reaches for without
/// reading anything. `{}` is refused so that reach lands on [`token`], which
/// states the join. Writing the join takes BOTH halves of one value, which an
/// `@` binding gives: match `inert @ Inert::MalformedPayload(e)` and join
/// `inert.token()` with `e.token()` — never a spelled-out
/// `"malformed_payload:"`. [`PayloadError`], whose token is whole on every
/// arm, does implement `Display`.
///
/// [`token`]: Inert::token
/// [`MalformedPayload`]: Inert::MalformedPayload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Inert {
    /// The home document is not published: [`FoldCtx::is_published`]
    /// answered `false` for it (AUTH-2.66 item 3; I7, AUTH-2.102). Decided
    /// after the home's account and ahead of every per-kind check, so a
    /// credential deposited in a DRAFT-homed document answers this whatever
    /// its shape, its payload or its home pin would otherwise earn. How a
    /// host answers the fact — the origin's exception set, v1's constant
    /// `true`, a mirror's guest visibility class — is stated on that method.
    ///
    /// [`FoldCtx::is_published`]: crate::FoldCtx::is_published
    Unpublished,
    /// The deposit cannot be read as its kind's shape, on any of three
    /// counts: the home is UNOWNED, so there is no H at all (AUTH-2.66
    /// item 2); a SLOT deviates from its kind's shape — for enroll/retire an
    /// empty `from` (AUTH-2.47, ahead of the parser) or a `to` that is not
    /// ONE address-form span (AUTH-2.46, AUTH-2.26), for the claim a `from`
    /// that is not H in address form or a `to` that is not EMPTY (AUTH-2.48);
    /// or the address an enroll/retire `to` resolves to is not an ACCOUNT
    /// (`FoldCtx::is_account`, AUTH-2.33). That last one answers THIS token —
    /// the fold has no `not_an_account`; that is the key-set READ row's
    /// (AUTH-2.58).
    MalformedShape,
    /// The payload could not be read or parsed (AUTH-1.27); the carried fault
    /// is this arm's sub-token on the wire, in the join [`Inert::token`]
    /// states.
    MalformedPayload(PayloadError),
    /// Credential link homed in a document of its account other than doc 1 —
    /// the home pin (AUTH-2.127, RES-17).
    NotDocOne,
    /// Own-space act on an account whose set has never been non-empty
    /// (outside the pre-claim bootstrap case) (AUTH-2.71, AUTH-2.76).
    NoHolder,
    /// An ENROLLMENT homed in neither the holder's space nor the account's
    /// genesis registry, or a genesis attempt on a seeded account — the
    /// latch — or the HANDOFF LATCH, tested inside the cell the genesis arm
    /// would otherwise honor: a genesis at an account beneath a
    /// bootstrap-tier account naming a key that already stands in the set
    /// that opens the account above it, the same token and no row of its
    /// own (AUTH-2.71).
    NotGenesisRegistry,
    /// A RETIREMENT homed outside the subject account's own space
    /// (AUTH-2.76): no ancestor retires a holder's keys.
    NotHolderRetirement,
    /// The retirement names the whole enrolled set (AUTH-2.74): the record
    /// is inert WHOLE; non-emptiness stays monotone (I3, AUTH-2.97).
    WouldEmpty,
    /// A HOLDER's own-space record that parses but changes nothing — the
    /// holder arms alone answer it (AUTH-2.69, AUTH-2.74). The same record
    /// anywhere else answers the refusal that decides it first — among the
    /// arms, `no_holder`, `not_genesis_registry` or `not_holder_retirement` —
    /// never this. The table is unchanged either way; the token is not
    /// (`Empty` is the parse-level sibling, AUTH-2.16).
    NothingChanged,
    /// A claim on an already-claimed board (AUTH-2.67 item 4; I6).
    AlreadyClaimed,
    /// A claim by a keyless account (AUTH-2.67 item 5).
    ClaimantKeyless,
    /// A claim by an account not on the bootstrap-delegated tier
    /// (AUTH-2.67 item 3 — `Some(Account(_))` and `None` alike).
    ClaimantNotTopLevel,
}

impl Inert {
    /// AUTH-2.55 — THE ONE AUTHORITY for the fold's `detail` tokens: the
    /// variant name in snake_case. Consumers (wire enumerations, conformance
    /// lists, face tables) cite this method, never transcribe it.
    ///
    /// A fold refusal's WIRE detail is this token — on the payload arm, this
    /// token, `:`, and the carried fault's [`PayloadError::token`]. ONE join,
    /// written by the consumer that marshals the refusal (skepd's
    /// `CredentialRefusal::token()`, AUTH-2.55) from these two methods, so no
    /// fold or payload token is spelled outside this crate. The join is stated
    /// here and only here; [`Inert::MalformedPayload`] and
    /// [`PayloadError::token`] cite it.
    pub fn token(&self) -> &'static str {
        match self {
            Inert::Unpublished => "unpublished",
            Inert::MalformedShape => "malformed_shape",
            Inert::MalformedPayload(_) => "malformed_payload",
            Inert::NotDocOne => "not_doc_one",
            Inert::NoHolder => "no_holder",
            Inert::NotGenesisRegistry => "not_genesis_registry",
            Inert::NotHolderRetirement => "not_holder_retirement",
            Inert::WouldEmpty => "would_empty",
            Inert::NothingChanged => "nothing_changed",
            Inert::AlreadyClaimed => "already_claimed",
            Inert::ClaimantKeyless => "claimant_keyless",
            Inert::ClaimantNotTopLevel => "claimant_not_top_level",
        }
    }
}
