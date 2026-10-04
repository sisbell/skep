//! THE NAMED STATES and THE VERDICT — what a resolution answers, as values a
//! UI renders and this crate never words.
//!
//! THE VERDICT (rm-2, owner-ruled 2026-09-25; REG-1.86 (e): "THE VERDICT
//! STANDS BESIDE THE READ"): a verifying reader holds a SECOND value beside
//! each record, one of the signed-ops record §3.5's FIVE values —
//! BEFORE-ATTESTATION, SIGNED, UNSIGNED, DISAVOWED, UNDETERMINABLE HERE —
//! and manufactures none from a missing input. The registry's own reads take
//! no input from `sig`; this crate's DECISION does: a record whose verdict is
//! not SIGNED is suppressed from the index and never consulted at a resolve
//! (the investigation §2.5, §6), and counted (`Index::suppressed`).
//!
//! THE FACES (REG-3.80's table; R2 (d)): every resolution outcome is a named
//! visible state and never a blank or a silent trust — UNREGISTERED,
//! RETIRED-WITH-HISTORY, BOUND-BUT-UNREACHABLE, unreachable-by-policy, THE
//! DIAL NOT MADE, BOUND-BUT-DISCLAIMED, THE HOP NOT MADE, the
//! live-enforcement face — and BOUND, the walk's answer. Two of them need
//! what this crate does not do: BOUND-BUT-DISCLAIMED reads the prefix the
//! board ASSERTS in its hello (REG-3.81) and the live-enforcement face reads
//! the AUTH-5.86 pair at the dial (REG-3.84); both are named here as
//! variants the caller fills once it has dialed, and this crate's walk never
//! answers them.

use skep_address::Address;
use skep_identity::{Enrolled, Fingerprint};

use crate::origin::{Dial, MemberKind, MemberOutcome, Term};

/// THE VERDICT — the signed-ops record §3.5's five values of "whose act was
/// this", spelled as that record enumerates them. A registry record's
/// verdict is judged at the record grade (REG-1.86 (e); 2b): the `sig`
/// member over the record frame under the set that opens the home's account
/// as of the record's own position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// At or below the board's claim entry, where there was no law yet
    /// (A1). No registry record stands there (REG-1.32), so this crate
    /// answers it of nothing; the value is named for the readers that share
    /// the enum.
    BeforeAttestation,
    /// A signature of a key of the home's account over the record's own
    /// content, verified as of the record's own position — the key's
    /// fingerprint, recovered by trial over the account's set and never read
    /// off the signature.
    Signed(Fingerprint),
    /// No signature of a key of the home's account over its own content: a
    /// `sig` absent, of no row's width, or verifying under no key of the set
    /// as of the position. A signature present and not verifying earns no
    /// word of its own.
    Unsigned,
    /// A disavowal record names the window the record's position falls in.
    /// The disavowal's row has no parser in this build, so this crate
    /// answers it of nothing; named for the readers that share the enum.
    Disavowed,
    /// This reader cannot check the signature: the board term is not held,
    /// the key set as of the position cannot be read, or the record's bytes
    /// cannot be fetched. The limit is the reader's; it never renders as
    /// unsigned.
    UndeterminableHere,
}

impl Verdict {
    /// Whether the verdict admits the record to the index — SIGNED alone
    /// (rm-2: an unsigned record's verdict is suppressed for the decision
    /// that rests on authenticity, and none is manufactured).
    pub fn admits(&self) -> bool {
        matches!(self, Verdict::Signed(_))
    }
}

/// A record beside its verdict (REG-1.86 (e)), at the position its link
/// committed (REG-1.10: a deposit's journal position is its LINK's), in the
/// home it is deposited in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged<T> {
    /// The link's committed position on the `/changes` feed — the deposit's
    /// position for every "by journal order" read.
    pub position: u64,
    /// The link's address, the name a later record's `replaces` member
    /// gives this one (REG-2.24).
    pub link: Address,
    /// The home the deposit sits in — a doc 1 (REG-2.18, REG-1.9).
    pub home: Address,
    /// The record as the index holds it.
    pub record: T,
    /// The verdict beside it.
    pub verdict: Verdict,
}

/// A BINDING as the index holds it (REG-2.19 to REG-2.21): the prefix it
/// binds, the account it names — the link's target, none at a targetless
/// binding, expulsion's and every retirement's one spelling — the binding it
/// replaces, and whether the walk HONORS it (REG-2.9, REG-2.24): an inert
/// binding stands in the history and moves no state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    pub prefix: Address,
    pub account: Option<Address>,
    pub replaces: Option<Address>,
    pub honored: bool,
}

/// An ENDPOINT deposit as the index holds it (REG-1.9, REG-1.10): the org's
/// ordered origins, the deposit it replaces, whether the currency rule
/// honors it, and whether the org's own `nullify` took it off the active
/// view (REG-1.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRecord {
    pub origins: Vec<String>,
    pub replaces: Option<Address>,
    pub honored: bool,
    pub nullified: bool,
}

/// A prefix's STANDING: the binding the walk holds current for it, and the
/// binding's whole history at that prefix on the AUDIT view (REG-2.8,
/// REG-2.14; REG-3.80's "its binding and its history") — every verified
/// binding at the prefix in journal order, honored and inert alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    pub prefix: Address,
    pub current: Judged<BindingRecord>,
    pub history: Vec<Judged<BindingRecord>>,
}

/// The successor a RETIRED prefix's ground record names (REG-3.83): the
/// vouched account and its own prefix. The succession ground's row has no
/// parser in this build, so the walk names none; the face then renders the
/// binding's retirement alone, as REG-3.83 has it where the read is not
/// made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Successor {
    pub account: Address,
    pub prefix: Option<Address>,
}

/// Why a BOUND account is unreachable (REG-3.80's BOUND-BUT-UNREACHABLE row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreachable {
    /// No honored endpoint deposit stands in the account's doc 1 yet — the
    /// interval between the binding's commit and the first deposit.
    NoEndpointYet,
    /// The last honored deposit was nullified and none stands before it.
    NullifiedLast,
    /// The first member of the current deposit names a host whose
    /// resolution yields no address — endpoint rot (REG-3.35: a name that
    /// yields none is not refused but dead).
    DeadOrigin { member: String },
}

/// THE FACES — every resolution outcome, REG-3.80's table as an enum. The
/// walk ([`crate::walk::resolve`]) answers the first seven; the last two are
/// the caller's to fill after the dial it alone makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A prefix no binding names: unknown is a visible state, never a
    /// silent trust.
    Unregistered { prefix: Address },
    /// A RETIRED binding — the current binding at the prefix names no
    /// account: that the org existed, with its history; the successor where
    /// a ground record names one, never UNREGISTERED.
    RetiredWithHistory { standing: Standing, successor: Option<Successor> },
    /// A BOUND account with no reachable endpoint: no honored deposit yet,
    /// the state a nullified last deposit leaves, or a dead origin — the
    /// prefix, its binding and its standing, never a silent absence.
    BoundButUnreachable {
        standing: Standing,
        keys: Vec<Enrolled>,
        endpoint: Option<Judged<EndpointRecord>>,
        cause: Unreachable,
        members: Vec<MemberOutcome>,
    },
    /// An endpoint record the resolver refuses (REG-3.34, REG-3.35), naming
    /// WHICH TERM refused — the scheme, or the host with the addresses THIS
    /// RESOLVER's own resolution of a name yielded.
    UnreachableByPolicy {
        standing: Standing,
        keys: Vec<Enrolled>,
        endpoint: Judged<EndpointRecord>,
        member: String,
        term: Term,
        members: Vec<MemberOutcome>,
    },
    /// THE DIAL NOT MADE (RES-28): the first member in the org's order is of
    /// an admitted kind whose transport this resolver does not hold, and no
    /// later member would dial — the member's kind named, the org's liveness
    /// unknown to this reader.
    DialNotMade {
        standing: Standing,
        keys: Vec<Enrolled>,
        endpoint: Judged<EndpointRecord>,
        member: String,
        kind: MemberKind,
        members: Vec<MemberOutcome>,
    },
    /// THE HOP NOT MADE (REG-3.82): a depth address whose walk reaches its
    /// parent — the longest prefix this board binds — and cannot make the
    /// next hop, that board being another mirror's (REG-3.32). The parent's
    /// own resolution rides beside it; nothing is promised about the child.
    HopNotMade { prefix: Address, parent: Box<Resolution> },
    /// BOUND: the binding, the account's key set, its current endpoint and
    /// the member this resolver WOULD dial — the first in the org's order it
    /// holds a transport for and whose terms pass — with the outcome of every
    /// member beside it (REG-3.34's one precedence).
    Bound {
        standing: Standing,
        keys: Vec<Enrolled>,
        endpoint: Judged<EndpointRecord>,
        dial: Dial,
        members: Vec<MemberOutcome>,
    },
    /// The board a prefix's current deposit names asserts a DIFFERENT prefix
    /// (REG-3.81) — read off the hello, which the caller alone receives.
    /// Named here; never answered by this crate's walk.
    BoundButDisclaimed { standing: Standing, asserted_prefix: String },
    /// The board's live enforcement state at the encounter (REG-3.84), the
    /// AUTH-5.86 pair read at the dial the caller alone makes. Named here;
    /// never answered by this crate's walk.
    LiveEnforcement { standing: Standing, claimant: Option<Address>, local_trust: bool },
}

impl Resolution {
    /// The face's name as REG-3.80's table spells it — a stable token a
    /// renderer keys on, not its copy.
    pub fn face(&self) -> &'static str {
        match self {
            Resolution::Unregistered { .. } => "UNREGISTERED",
            Resolution::RetiredWithHistory { .. } => "RETIRED-WITH-HISTORY",
            Resolution::BoundButUnreachable { .. } => "BOUND-BUT-UNREACHABLE",
            Resolution::UnreachableByPolicy { .. } => "unreachable-by-policy",
            Resolution::DialNotMade { .. } => "THE DIAL NOT MADE",
            Resolution::HopNotMade { .. } => "THE HOP NOT MADE",
            Resolution::Bound { .. } => "BOUND",
            Resolution::BoundButDisclaimed { .. } => "BOUND-BUT-DISCLAIMED",
            Resolution::LiveEnforcement { .. } => "the live-enforcement face",
        }
    }

    /// The standing the face carries, where it renders one — every face but
    /// UNREGISTERED and THE HOP NOT MADE, whose parent carries its own.
    pub fn standing(&self) -> Option<&Standing> {
        match self {
            Resolution::Unregistered { .. } | Resolution::HopNotMade { .. } => None,
            Resolution::RetiredWithHistory { standing, .. }
            | Resolution::BoundButUnreachable { standing, .. }
            | Resolution::UnreachableByPolicy { standing, .. }
            | Resolution::DialNotMade { standing, .. }
            | Resolution::Bound { standing, .. }
            | Resolution::BoundButDisclaimed { standing, .. }
            | Resolution::LiveEnforcement { standing, .. } => Some(standing),
        }
    }
}
