//! Verdicts, effects, and the inert vocabulary — AUTH-2.51–2.55.

use skep_address::Address;

use crate::key::Fingerprint;
use crate::keyset::Enrolled;
use crate::payload::PayloadError;

/// A deposit's fold verdict (AUTH-2.51).
///
/// `classify` is the verdict `step` would reach without applying it
/// (AUTH-2.57) — the daemon's precheck and the mirror's oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not a credential deposit at all (AUTH-2.77).
    ///
    /// It covers nullifies, `assert_sup` claims, retraction/supersession
    /// tuples and unrecognized types — state unchanged. The fold reads
    /// deposits, the audit view: a nullified credential link still counts
    /// (AUTH-2.78, I8 AUTH-2.103).
    NotCredential,
    /// A credential-shaped deposit the fold refuses (AUTH-2.54).
    ///
    /// The table is unchanged and the reason is the token.
    Inert(Inert),
    /// An honored deposit; the carried effect is what `apply` posts.
    Honored(Effect),
}

/// A faithful description of the change `apply` posts (AUTH-2.51, AUTH-2.52).
///
/// `account` names the account each arm concerns, which is not the same fact
/// on all four: on `Genesis`/`Enroll`/`Retire` it is the account whose key
/// set the post amends; on `Claim` it is the claimant, and that arm amends
/// no set — it posts `claimant`. `apply` reads the effect and decides
/// nothing (AUTH-2.53).
///
/// **Postcondition.** `keys`, `added` and `removed` are in the record's own
/// entry order ([`parse_enroll`](crate::parse_enroll) /
/// [`parse_retire`](crate::parse_retire)'s postcondition): `Genesis`' `keys`
/// are every entry of the record in that order, and `Enroll`'s `added` and
/// `Retire`'s `removed` are the subsequence of it the arm's own filter
/// admits. Nothing sorts, dedups or re-groups them.
///
/// `apply` is order-blind — its posts go into ordered maps and the parsers
/// left the entries duplicate-free (AUTH-2.15), so no permutation changes the
/// key table. The order is promised because the effect is *read*: the
/// daemon's key-decodability courtesy, in `skep-core`, walks a bounded prefix
/// of `keys`/`added`, so under a different order an over-cap record earns a
/// different refusal token; and `classify` is a mirror's oracle (AUTH-2.57),
/// so two implementations folding one record must answer one `Effect` under
/// this type's `PartialEq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// The genesis arm's post (AUTH-2.70).
    ///
    /// It carries the account and the keys the step seeds it with, in the
    /// same `Enrolled` shape `Enroll` uses — never the bare fingerprint,
    /// because the apply constructs the map's values (AUTH-2.52). Fires at
    /// most once per account (I5, AUTH-2.100).
    Genesis {
        /// The seeded account.
        account: Address,
        /// The seeding keys: every entry of the record, in its entry order.
        ///
        /// Their flags are as the entries carry them.
        keys: Vec<Enrolled>,
    },
    /// The holder-enrollment post (AUTH-2.69).
    ///
    /// It carries each added key with the flag it enters under.
    Enroll {
        /// The enrolling account.
        account: Address,
        /// The keys actually added (`∉ enrolled ∧ ∉ retired`).
        ///
        /// They are in the record's entry order.
        added: Vec<Enrolled>,
    },
    /// The retirement post (AUTH-2.74): fingerprints only.
    Retire {
        /// The retiring account.
        account: Address,
        /// The fingerprints removed (`F ∩ enrolled`).
        ///
        /// They are in the record's entry order.
        removed: Vec<Fingerprint>,
    },
    /// The claim post, `claimant = Some(account)` (AUTH-2.67 item 6).
    ///
    /// There is at most one ever (I6, AUTH-2.101).
    Claim {
        /// The claiming account.
        account: Address,
    },
}

/// The inert vocabulary (AUTH-2.54).
///
/// A verdict and never a public `Err` — the one `Result` it rides in is the
/// fold's private early exit, `subject_and_record`, whose refusal the arm
/// entry hands straight back as a [`Verdict`] — so it is not a
/// `std::error::Error`, and deliberately not `Display` either: a refusal's
/// wire detail is [`token`]'s string on every arm but [`MalformedPayload`],
/// whose detail is the join, so a `Display` writing `token()` alone would
/// answer `malformed_payload` where the detail is
/// `malformed_payload:bad_record` — half a wire detail, from the one trait a
/// consumer reaches for without reading anything. `{}` is refused so that
/// reach lands on [`detail`], which *writes* the join; a consumer marshals a
/// refusal by citing that one method and never spells `"malformed_payload:"`
/// for itself. [`PayloadError`], whose token is whole on every arm, does
/// implement `Display`.
///
/// [`token`]: Inert::token
/// [`detail`]: Inert::detail
/// [`MalformedPayload`]: Inert::MalformedPayload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Inert {
    /// The home document is not published (AUTH-2.66 item 3; I7, AUTH-2.102).
    ///
    /// [`FoldCtx::is_published`] answered `false` for it. Decided after the
    /// home's account and ahead of every per-kind check, so a credential
    /// deposited in a draft-homed document answers this whatever its shape,
    /// its payload or its home pin would otherwise earn. How a host answers
    /// the fact — the origin's exception set, v1's constant `true`, a
    /// mirror's guest visibility class — is stated on that method.
    ///
    /// [`FoldCtx::is_published`]: crate::FoldCtx::is_published
    Unpublished,
    /// The deposit cannot be read as its kind's shape, on any of three counts.
    ///
    /// The home is unowned, so there is no H at all (AUTH-2.66 item 2); a slot
    /// deviates from its kind's shape — for enroll/retire an empty `from`
    /// (AUTH-2.47, ahead of the parser) or a `to` that is not one
    /// address-form span (AUTH-2.46, AUTH-2.26), for the claim a `from` that
    /// is not H in address form or a `to` that is not empty (AUTH-2.48); or
    /// the address an enroll/retire `to` resolves to is not an account
    /// (`FoldCtx::is_account`, AUTH-2.33). That last one answers this token —
    /// the fold has no `not_an_account`; that is the key-set read row's
    /// (AUTH-2.58).
    MalformedShape,
    /// The payload could not be read or parsed (AUTH-1.27).
    ///
    /// The carried fault is this arm's sub-token on the wire, in the join
    /// [`Inert::detail`] writes.
    MalformedPayload(PayloadError),
    /// A credential link homed in a document of its account other than doc 1.
    ///
    /// The home pin refuses it (AUTH-2.127, RES-17).
    NotDocOne,
    /// An own-space act on an account whose set has never been non-empty.
    ///
    /// The pre-claim bootstrap case is outside it (AUTH-2.71, AUTH-2.76).
    NoHolder,
    /// An enrollment refused for where it is homed, or by a latch (AUTH-2.71).
    ///
    /// It is an enrollment homed in neither the holder's space nor the
    /// account's genesis registry; or a genesis attempt on a seeded account —
    /// the latch; or the handoff latch, tested inside the cell the genesis arm
    /// would otherwise honor: a genesis at an account beneath a bootstrap-tier
    /// account naming a key that already stands in the set that opens the
    /// account above it, the same token and no row of its own.
    NotGenesisRegistry,
    /// A retirement homed outside the subject account's own space (AUTH-2.76).
    ///
    /// No ancestor retires a holder's keys.
    NotHolderRetirement,
    /// The retirement names the whole enrolled set (AUTH-2.74).
    ///
    /// The record is inert whole; non-emptiness stays monotone (I3,
    /// AUTH-2.97).
    WouldEmpty,
    /// A holder's own-space record that parses but changes nothing.
    ///
    /// The holder arms alone answer it (AUTH-2.69, AUTH-2.74). The same record
    /// anywhere else answers the refusal that decides it first — among the
    /// arms, `no_holder`, `not_genesis_registry` or `not_holder_retirement` —
    /// never this. The table is unchanged either way; the token is not
    /// (`Empty` is the parse-level sibling, AUTH-2.16).
    NothingChanged,
    /// A claim on an already-claimed board (AUTH-2.67 item 4; I6).
    AlreadyClaimed,
    /// A claim by a keyless account (AUTH-2.67 item 5).
    ClaimantKeyless,
    /// A claim by an account not on the bootstrap-delegated tier.
    ///
    /// The delegator `Some(Account(_))` and `None` alike answer it (AUTH-2.67
    /// item 3).
    ClaimantNotTopLevel,
}

impl Inert {
    /// Returns the variant name in snake_case, the `detail` token (AUTH-2.55).
    ///
    /// It is the one authority for the fold's `detail` tokens. Consumers (wire
    /// enumerations, conformance lists, face tables) are to cite this method,
    /// never transcribe it; `skep-client`'s deposit faces transcribe the
    /// tokens they match.
    ///
    /// This is the token and not always the whole wire detail: on
    /// [`Inert::MalformedPayload`] the detail is this token joined to the
    /// carried fault's, which [`Inert::detail`] writes. A consumer marshaling
    /// a refusal wants that one; this is the arm-by-arm vocabulary.
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

    /// Returns the wire `detail` a fold refusal carries (AUTH-2.55).
    ///
    /// It is [`token`] on every arm but [`MalformedPayload`], and on that arm
    /// its token, `:`, and the carried fault's [`PayloadError::token`]
    /// (AUTH-1.28). The join is this crate's to *write* and not merely to
    /// describe, as [`PayloadError`]'s own one-argument join is
    /// (`duplicate_key:<n>`) — so a consumer marshaling a refusal cites this
    /// one method and spells no token and no separator (`skep-core`'s
    /// `CredentialRefusal::token()` is one arm over it).
    ///
    /// [`token`]: Inert::token
    /// [`MalformedPayload`]: Inert::MalformedPayload
    pub fn detail(&self) -> String {
        match self {
            Inert::MalformedPayload(e) => format!("{}:{}", self.token(), e.token()),
            _ => self.token().to_owned(),
        }
    }
}
