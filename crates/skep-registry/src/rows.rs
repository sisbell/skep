//! THE ROWS — the registry's kinds and subtype rows at the addresses
//! commons-map pins (REG-1.14, REG-1.15, REG-1.26; the map's table "THE
//! REGISTRY'S ROWS"), spelled ONCE as one table and read through held pins,
//! as the engine's commons ledger holds its own. How many kinds and rows
//! there are is read off the lists — [`Kind::ALL`], [`Subtype::ALL`],
//! [`rows()`] — and written as a tally nowhere (REG-1.25, REG-1.26).
//!
//! The KINDS stand on the registry range's ordinals, `3.54`–`3.59` as the
//! list stands (REG-1.23 to REG-1.25), and the SUBTYPE rows nest under their
//! kinds by prefix (REG-1.20; L10: hierarchy is prefix), each subtype its
//! own wire type at the type slot (REG-1.21). THE BARE ORDINAL IS A TEST,
//! NOT A PER-KIND ANSWER (REG-1.18): a kind that reads ONE way — the
//! binding, the endpoint, `successor-of` — carries its deposits on its own
//! ordinal and owes no subtype row; a kind that reads MORE than one way —
//! the takedown record, the policy link, the registration — carries NONE on
//! its bare ordinal, every reading a row at a prefix under it. THE TEST
//! RECURSES TO A ROW: a subtype row that itself reads more than one way is
//! a PARENT ROW — the registration's `request` and `reply` — its readings
//! rows at a prefix under its own address ([`Subtype::parent`]) and its own
//! address carrying no deposit, so a deposit rides a LEAF and never a row
//! with rows beneath it, at whatever depth. The map's "Deposits" column is
//! that test, computed off the row each subtype stands directly beneath and
//! never stored: [`Row::carries_deposits`], whose doc says why a subtype row
//! the table gains moves no row already in it, and why a kind that reads ONE
//! way never takes one.
//!
//! THE ORDER (the map): the first three kinds in REG-1.14's order at `3.55`,
//! `3.56`, `3.57`; `successor-of`, REG-1.14's fourth kind, at `3.59` where
//! the build already had it; the policy link, its fifth, at `3.58`, the
//! ordinal the cut home-link kind freed; and the registration, its sixth, at
//! `3.54`, the reserve ordinal beside `3.55`, which keeps the registry's
//! ordinals one run. The subtype ordinals follow REG-1.15's row order, and
//! the rows under a parent row follow that parent's own order there.
//!
//! Every address is the ghost home document's subspace-3 element —
//! `1.1.0.1.0.1 · 0 · 3 · <ordinals>`, the commons' type subspace, where
//! nothing is ever minted — spelled here from [`COMMONS_TYPE_PREFIX`], read
//! back here ([`registry_range_ordinal`]), and nowhere else in this crate.
//! The engine's ledger reads these pins, and the daemon's write-path classes
//! read them through it. Two spellings in shipped code stand outside this
//! table, each held equal to its pin by the suite that can see both: the
//! ledger's own `successor-of`, held equal to [`t_successor_of`] by the
//! ledger's tests, and the insert door's deposit class
//! (`skep-arrangement`'s `DEPOSIT_CLASS_PATHS`), whose registry members —
//! the binding, the endpoint and the registration's six deposit-carrying
//! rows — the engine ledger's tests and the daemon's suite
//! (`skepd/tests/it/deposit_class.rs`) hold equal to this table's.

use std::ops::RangeInclusive;
use std::sync::LazyLock;

use skep_address::{validate, Address, Nat, Tumbler};

/// The KINDS (REG-1.14), in the order its table lists them, each reading
/// as many ways as its table's last column gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The BINDING — the registration record itself: prefix → account. It
    /// reads one way, its deposits riding its bare ordinal.
    Binding,
    /// The ENDPOINT — the org's own endpoint deposit (REG-1.9). It reads one
    /// way, its deposits riding its bare ordinal.
    Endpoint,
    /// The TAKEDOWN RECORD's kind — the operator's serving-layer instrument
    /// and LIFTED, its reversal. It reads two ways, each a subtype row under
    /// this one: the BASE reading, the instrument itself
    /// ([`Subtype::TakedownBase`]; REG-1.86: this kind's row and that reading
    /// "being one record"), and LIFTED ([`Subtype::TakedownLifted`]). No
    /// deposit rides this kind's bare ordinal (REG-1.18;
    /// [`Row::carries_deposits`]).
    TakedownRecord,
    /// `successor-of` — the succession claim, at the fork's seat alone. It
    /// reads one way, its deposits riding its bare ordinal.
    SuccessorOf,
    /// The POLICY LINK's kind — the link naming the published policy
    /// document, and the records that ride under it. It reads five ways,
    /// each a subtype row under this one: the link's OWN reading, the link
    /// itself ([`Subtype::PolicyLinkOwn`]; REG-1.86: this kind's row and that
    /// reading "being one record"), the disavowal, an expulsion's and a
    /// succession's ground records, and the org-chosen succession policy. No
    /// deposit rides this kind's bare ordinal (REG-1.18;
    /// [`Row::carries_deposits`]).
    PolicyLink,
    /// The REGISTRATION's kind — a door's admission records (REG-4.67). It
    /// reads four ways, each a subtype row under this one: the REQUEST and
    /// the REPLY, parent rows whose own readings are rows beneath them
    /// ([`Subtype::Request`], [`Subtype::Reply`]), the VOUCH
    /// ([`Subtype::Vouch`]) and the APPROVAL, a link alone
    /// ([`Subtype::Approval`]). No deposit rides this kind's bare ordinal
    /// (REG-1.18; [`Row::carries_deposits`]).
    Registration,
}

impl Kind {
    /// Every kind, in REG-1.14's order — the completeness arm's list, and
    /// what every count of the kinds is read off (REG-1.25).
    pub const ALL: &'static [Kind] = &[
        Kind::Binding,
        Kind::Endpoint,
        Kind::TakedownRecord,
        Kind::SuccessorOf,
        Kind::PolicyLink,
        Kind::Registration,
    ];

    /// The kind's name as the rules spell it — what the seeding check's
    /// refusal sentence names it by ([`crate::SeedingRefusal`]).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::Binding => "the binding",
            Kind::Endpoint => "the endpoint",
            Kind::TakedownRecord => "the takedown record",
            Kind::SuccessorOf => "successor-of",
            Kind::PolicyLink => "the policy link",
            Kind::Registration => "the registration",
        }
    }

    /// The kind's own row in the table ([`rows()`]), held.
    pub fn row(self) -> &'static Row {
        rows().iter().find(|r| r.of == RowOf::Kind(self)).expect("the table holds every kind's row")
    }
}

/// The SUBTYPE rows (REG-1.15), in the order its table lists them — a row
/// at any depth under its kind, a PARENT ROW ahead of the rows beneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subtype {
    /// The takedown record's BASE reading — the operator's instrument itself.
    TakedownBase,
    /// LIFTED — the takedown record's reversal.
    TakedownLifted,
    /// The policy link's OWN reading — the link itself, naming the published
    /// policy document; link-alone. A row no rule writes: the door's policy
    /// is found at its well-known document and by no link (REG-1.15,
    /// REG-4.131), and the row stands all the same.
    PolicyLinkOwn,
    /// The DISAVOWAL — the one type of it, an author's in their own doc 1
    /// or an officer's at the policy home.
    Disavowal,
    /// An expulsion's GROUND RECORD.
    ExpulsionGround,
    /// A succession's GROUND RECORD.
    SuccessionGround,
    /// The ORG-CHOSEN SUCCESSION POLICY.
    SuccessionPolicy,
    /// The registration's REQUEST — a PARENT ROW: it reads more than one
    /// way, its kinds rows beneath it, and no deposit rides it (REG-1.18).
    Request,
    /// The request's FRESH kind — a request from an org with no board yet.
    RequestFresh,
    /// The request's BOARD-CARRIES-ON kind — a request from an org that
    /// keeps its own board.
    RequestBoardCarriesOn,
    /// The registration's REPLY — a PARENT ROW: its answers are rows beneath
    /// it, and no deposit rides it (REG-1.18).
    Reply,
    /// The APPROVED answer.
    ReplyApproved,
    /// The REFUSED answer — a fault in the request, never a judgment of the
    /// person.
    ReplyRefused,
    /// The DENIED answer — an officer's, citing a clause of the door's
    /// policy.
    ReplyDenied,
    /// The VOUCH — one account speaking for an applicant.
    Vouch,
    /// The APPROVAL — the link tying the account a registrar made to the
    /// request it answers; link-alone.
    Approval,
}

impl Subtype {
    /// Every subtype row, in REG-1.15's row order — the completeness arm's
    /// list, and what every count of the subtype rows is read off
    /// (REG-1.26). A parent row stands ahead of the rows beneath it.
    pub const ALL: &'static [Subtype] = &[
        Subtype::TakedownBase,
        Subtype::TakedownLifted,
        Subtype::PolicyLinkOwn,
        Subtype::Disavowal,
        Subtype::ExpulsionGround,
        Subtype::SuccessionGround,
        Subtype::SuccessionPolicy,
        Subtype::Request,
        Subtype::RequestFresh,
        Subtype::RequestBoardCarriesOn,
        Subtype::Reply,
        Subtype::ReplyApproved,
        Subtype::ReplyRefused,
        Subtype::ReplyDenied,
        Subtype::Vouch,
        Subtype::Approval,
    ];

    /// The kind this subtype row nests under (REG-1.20), at whatever depth:
    /// a row beneath a parent row names its parent's kind.
    pub fn kind(self) -> Kind {
        match self {
            Subtype::TakedownBase | Subtype::TakedownLifted => Kind::TakedownRecord,
            Subtype::PolicyLinkOwn
            | Subtype::Disavowal
            | Subtype::ExpulsionGround
            | Subtype::SuccessionGround
            | Subtype::SuccessionPolicy => Kind::PolicyLink,
            Subtype::Request
            | Subtype::RequestFresh
            | Subtype::RequestBoardCarriesOn
            | Subtype::Reply
            | Subtype::ReplyApproved
            | Subtype::ReplyRefused
            | Subtype::ReplyDenied
            | Subtype::Vouch
            | Subtype::Approval => Kind::Registration,
        }
    }

    /// The PARENT ROW this row stands directly beneath, for a row under a
    /// row (REG-1.15, REG-1.18); `None` for a row directly under its kind's.
    /// A parent row is a subtype row that itself reads more than one way:
    /// its readings are rows at a prefix under its own address (REG-1.20),
    /// and its own address carries no deposit ([`Row::carries_deposits`]).
    pub fn parent(self) -> Option<Subtype> {
        match self {
            Subtype::RequestFresh | Subtype::RequestBoardCarriesOn => Some(Subtype::Request),
            Subtype::ReplyApproved | Subtype::ReplyRefused | Subtype::ReplyDenied => {
                Some(Subtype::Reply)
            }
            Subtype::TakedownBase
            | Subtype::TakedownLifted
            | Subtype::PolicyLinkOwn
            | Subtype::Disavowal
            | Subtype::ExpulsionGround
            | Subtype::SuccessionGround
            | Subtype::SuccessionPolicy
            | Subtype::Request
            | Subtype::Reply
            | Subtype::Vouch
            | Subtype::Approval => None,
        }
    }

    /// The row's name as the rules spell it — what the seeding check's
    /// refusal sentence names it by ([`crate::SeedingRefusal`]).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Subtype::TakedownBase => "the takedown record's base reading",
            Subtype::TakedownLifted => "lifted",
            Subtype::PolicyLinkOwn => "the policy link's own reading",
            Subtype::Disavowal => "the disavowal",
            Subtype::ExpulsionGround => "an expulsion's ground record",
            Subtype::SuccessionGround => "a succession's ground record",
            Subtype::SuccessionPolicy => "the org-chosen succession policy",
            Subtype::Request => "the request",
            Subtype::RequestFresh => "the request's fresh kind",
            Subtype::RequestBoardCarriesOn => "the request's board-carries-on kind",
            Subtype::Reply => "the reply",
            Subtype::ReplyApproved => "the approved answer",
            Subtype::ReplyRefused => "the refused answer",
            Subtype::ReplyDenied => "the denied answer",
            Subtype::Vouch => "the vouch",
            Subtype::Approval => "the approval",
        }
    }

    /// The subtype's row in the table ([`rows()`]), held — nested under its
    /// kind's ([`Subtype::kind`]), and under its parent row's where it has
    /// one ([`Subtype::parent`]), each of which the subtype names, so no
    /// caller names either beside it.
    pub fn row(self) -> &'static Row {
        rows()
            .iter()
            .find(|r| r.of == RowOf::Subtype(self))
            .expect("the table holds every subtype row")
    }
}

/// What a row is the row OF: a kind, whose own row sits at its bare
/// ordinal, or a subtype, whose row nests under the row of the kind it
/// names (REG-1.20) — directly, or beneath a parent row of that kind
/// ([`RowOf::above`]). A subtype row's kind and parent are read off its
/// subtype ([`RowOf::kind`]), so a row whose kind and subtype disagree is no
/// value of this type. The inverse of [`Kind::row`] and [`Subtype::row`]:
/// `kind.row().of == RowOf::Kind(kind)`, and `subtype.row().of ==
/// RowOf::Subtype(subtype)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowOf {
    /// A kind's own row, at its bare ordinal.
    Kind(Kind),
    /// A subtype row, under its kind's — at any depth.
    Subtype(Subtype),
}

impl RowOf {
    /// The kind the row belongs to — its own, or the one its subtype nests
    /// under ([`Subtype::kind`]).
    pub fn kind(self) -> Kind {
        match self {
            RowOf::Kind(kind) => kind,
            RowOf::Subtype(subtype) => subtype.kind(),
        }
    }

    /// The subtype, for a subtype row; `None` for a kind's own row.
    pub fn subtype(self) -> Option<Subtype> {
        match self {
            RowOf::Kind(_) => None,
            RowOf::Subtype(subtype) => Some(subtype),
        }
    }

    /// The row this row stands DIRECTLY beneath (REG-1.20): `None` for a
    /// kind's own row, which stands beneath none; a subtype's parent row
    /// where it has one ([`Subtype::parent`]), else its kind's own row. The
    /// one step REG-1.18's test and the completeness arm both walk: a row
    /// carries deposits exactly where no row names it here
    /// ([`Row::carries_deposits`]), and a row's address is sought at a
    /// prefix under the row this names ([`crate::seeding_check`]).
    pub fn above(self) -> Option<RowOf> {
        match self {
            RowOf::Kind(_) => None,
            RowOf::Subtype(subtype) => Some(match subtype.parent() {
                Some(parent) => RowOf::Subtype(parent),
                None => RowOf::Kind(subtype.kind()),
            }),
        }
    }

    /// The row's name as the rules spell it ([`Kind::name`],
    /// [`Subtype::name`]).
    pub(crate) fn name(self) -> &'static str {
        match self {
            RowOf::Kind(kind) => kind.name(),
            RowOf::Subtype(subtype) => subtype.name(),
        }
    }
}

/// A registry row as a value: what it is the row OF ([`RowOf`]), its
/// address, and the `type` string its body carries where it carries one.
/// The commons-map pins are [`rows()`]'s, and every `&'static Row` this
/// crate hands out — [`Kind::row`], [`Subtype::row`], [`row_at`] — is one of
/// them; a `Row` value as such promises its fields and no more. The fields
/// are public and the type is `Clone` so a suite can build a list that
/// differs from [`rows()`] by one row and hand it to the seeding check
/// ([`crate::seeding_check`]), whose refusals are proved on such lists and
/// which reads each list as the rows it is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// What the row is the row of: a kind, or a subtype under its kind.
    pub of: RowOf,
    /// The row's address: the ghost home document's subspace-3 element.
    pub address: Address,
    /// The `type` member's string where the row's record carries a body
    /// (REG-1.86 (a)) — the row's own name, never a parent's. None at every
    /// other row: the link-alone rows (lifted, the policy link's own
    /// reading, `successor-of`, the registration's approval), which carry
    /// no body at all, and the rows that carry no deposit — the bare
    /// ordinals of the takedown record, the policy link and the
    /// registration, and the parent rows `request` and `reply` (REG-1.18).
    /// The binding's and the endpoint's are the strings [`crate::encode`]
    /// writes and [`crate::parse`] holds a body to, and the registration's
    /// six the strings [`crate::encode_registration`] and
    /// [`crate::parse_registration`] do.
    pub type_value: Option<&'static str>,
}

impl Row {
    /// The map's "Deposits" column for the row OF `of`: whether a deposit
    /// rides that row's address — REG-1.18's test, which every reader of a
    /// kind's or a row's deposits reads — answered off `of` alone and never
    /// off `address`, so a row of the table ([`rows()`]) answers for its own
    /// address, and a row a suite builds at another address still answers
    /// for its `of`. A deposit rides a LEAF: a row carries deposits exactly
    /// where no subtype row stands directly beneath it ([`RowOf::above`]) —
    /// a kind that reads ONE way, and every subtype row but a PARENT ROW —
    /// and none where its readings are rows under it, a kind's bare ordinal
    /// and a parent row's address alike, the test recursing to a row.
    /// Computed off [`Subtype::ALL`] and never stored, so a subtype row the
    /// table gains (REG-1.15) carries deposits by the test itself once its
    /// subtype joins `Subtype::ALL`, as the completeness arm requires of
    /// every subtype, and moves no row already in the table. A new reading
    /// is the takedown record's, the policy link's or the registration's —
    /// or a further row under `request` or `reply` — which take one at no
    /// cost, their own addresses carrying no deposit already (REG-1.19). A
    /// kind that reads ONE way takes no subtype row, and a row that already
    /// carries deposits never becomes a parent, since a row under either
    /// would leave the deposits already on its address, which no rewrite
    /// reaches (REG-1.60), on an address this test reads as carrying none —
    /// so its later form is the MEMBER form and never a row beneath it
    /// (REG-1.86, HOW A FORM CHANGES LATER).
    pub fn carries_deposits(&self) -> bool {
        !Subtype::ALL.iter().any(|s| RowOf::Subtype(*s).above() == Some(self.of))
    }

    /// The row's ORDINAL PATH: its address less the ghost home document —
    /// the commons' type subspace `3` then the row's ordinals, dotted
    /// decimal, `3.54.1.1` for the request's fresh kind. The spelling a
    /// registration request's signed `shape` member names its own row by
    /// (REG-1.86 (c); REG-4.104), the same on every board, the rows standing
    /// at the same local addresses everywhere (REG-1.32). Read off
    /// `address`'s element field, so a row a suite builds at another address
    /// answers that address's path; an address with no element field — which
    /// no row of the table holds — answers the empty string.
    pub fn ordinal_path(&self) -> String {
        let element = self.address.element_field().unwrap_or(&[]);
        element.iter().map(ToString::to_string).collect::<Vec<_>>().join(".")
    }
}

/// The commons' type subspace of the ghost home document, `1.1.0.1.0.1 · 0
/// · 3` — the eight components ahead of a row's ordinals, spelled once.
const COMMONS_TYPE_PREFIX: [u32; 8] = [1, 1, 0, 1, 0, 1, 0, 3];

/// THE REGISTRY RANGE — the ordinals `3.54`–`3.59` the kinds take as
/// commons-map's allocation ledger stands (REG-1.23, REG-1.24): the count
/// arm's bound (REG-1.25), each kind on a bare ordinal of its own inside it
/// and no two on one. Not the reserve commons-map names, `3.51`–`3.59`: the
/// reserve's name is no range (REG-1.23; REG-1.37 (b)), and its
/// `3.51`–`3.53` stay unallocated, no ordinal of this one (REG-1.24).
pub(crate) const REGISTRY_RANGE: RangeInclusive<u32> = 54..=59;

/// A commons type address: the commons' type subspace `1.1.0.1.0.1.0.3`
/// then `ordinals` — one for a kind's row, the kind's then the subtype's for
/// a subtype row, and one more for a row under a parent row.
///
/// THE CALLER OWES one or more ordinals, each positive: a row is an element
/// at positive ordinals — a zero among them would be a fourth zero
/// component, which no T4-valid address holds — and the table below spells
/// none other. Each obligation broken PANICS by a check of its own whose
/// message names it; given both, the address is T4-valid by construction
/// (the prefix's three zeros, none adjacent, then positive ordinals alone),
/// the supplier's own guarantee.
///
/// Public for the readers that name a commons type the table does not hold:
/// `skep-resolve`, which builds with it the credential types `3.1`–`3.3`
/// its mirror's fold tells a stored link's kind by, and the suites that
/// spell a row at an ordinal off the table to prove the seeding check's
/// arms.
pub fn commons_type(ordinals: &[u32]) -> Address {
    assert!(!ordinals.is_empty(), "a commons row names at least one ordinal");
    assert!(!ordinals.contains(&0), "a commons row's ordinals are positive");
    let comps = COMMONS_TYPE_PREFIX.iter().chain(ordinals).map(|&c| Nat::from(c));
    let tumbler = Tumbler::new(comps).expect("the components are nonempty");
    validate(tumbler).expect("a subspace-3 element at positive ordinals is T4-valid")
}

/// The ordinal of the registry range whose [`commons_type`] `a` IS — a bare
/// ordinal inside [`REGISTRY_RANGE`], where a kind's row sits — else `None`:
/// what the seeding check's count arm holds each kind row to.
pub(crate) fn registry_range_ordinal(a: &Address) -> Option<u32> {
    let mut range = REGISTRY_RANGE;
    range.find(|&ordinal| *a == commons_type(&[ordinal]))
}

/// The table's spelling of one row — what [`rows`] builds a [`Row`] from.
struct Spelling {
    of: RowOf,
    ordinals: &'static [u32],
    type_value: Option<&'static str>,
}

/// THE TABLE, in the map's order: the kinds by ordinal, each followed by
/// its subtype rows where it has any, a parent row by the rows beneath it.
const SPELLINGS: &[Spelling] = &[
    Spelling { of: RowOf::Kind(Kind::Registration), ordinals: &[54], type_value: None },
    Spelling { of: RowOf::Subtype(Subtype::Request), ordinals: &[54, 1], type_value: None },
    Spelling {
        of: RowOf::Subtype(Subtype::RequestFresh),
        ordinals: &[54, 1, 1],
        type_value: Some("fresh"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::RequestBoardCarriesOn),
        ordinals: &[54, 1, 2],
        type_value: Some("board-carries-on"),
    },
    Spelling { of: RowOf::Subtype(Subtype::Reply), ordinals: &[54, 2], type_value: None },
    Spelling {
        of: RowOf::Subtype(Subtype::ReplyApproved),
        ordinals: &[54, 2, 1],
        type_value: Some("approved"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::ReplyRefused),
        ordinals: &[54, 2, 2],
        type_value: Some("refused"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::ReplyDenied),
        ordinals: &[54, 2, 3],
        type_value: Some("denied"),
    },
    Spelling { of: RowOf::Subtype(Subtype::Vouch), ordinals: &[54, 3], type_value: Some("vouch") },
    Spelling { of: RowOf::Subtype(Subtype::Approval), ordinals: &[54, 4], type_value: None },
    Spelling { of: RowOf::Kind(Kind::Binding), ordinals: &[55], type_value: Some("binding") },
    Spelling { of: RowOf::Kind(Kind::Endpoint), ordinals: &[56], type_value: Some("endpoint") },
    Spelling { of: RowOf::Kind(Kind::TakedownRecord), ordinals: &[57], type_value: None },
    Spelling {
        of: RowOf::Subtype(Subtype::TakedownBase),
        ordinals: &[57, 1],
        type_value: Some("takedown"),
    },
    Spelling { of: RowOf::Subtype(Subtype::TakedownLifted), ordinals: &[57, 2], type_value: None },
    Spelling { of: RowOf::Kind(Kind::PolicyLink), ordinals: &[58], type_value: None },
    Spelling { of: RowOf::Subtype(Subtype::PolicyLinkOwn), ordinals: &[58, 1], type_value: None },
    Spelling {
        of: RowOf::Subtype(Subtype::Disavowal),
        ordinals: &[58, 2],
        type_value: Some("disavowal"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::ExpulsionGround),
        ordinals: &[58, 3],
        type_value: Some("expulsion-ground"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::SuccessionGround),
        ordinals: &[58, 4],
        type_value: Some("succession-ground"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::SuccessionPolicy),
        ordinals: &[58, 5],
        type_value: Some("succession-policy"),
    },
    Spelling { of: RowOf::Kind(Kind::SuccessorOf), ordinals: &[59], type_value: None },
];

/// THE ROWS, held once, in THE MAP'S ORDER — ascending in the tumbler order
/// (T1): the kinds by ordinal, `3.54` to `3.59`, each followed by its
/// subtype rows by theirs and a parent row by the rows beneath it, so the
/// registration's `3.54` and its rows stand ahead of the binding's `3.55`,
/// and the policy link's `3.58` and its readings ahead of `successor-of`'s
/// `3.59`, though [`Kind::ALL`]'s REG-1.14 order lists `successor-of` ahead
/// of the policy link and the registration last. A reader that zips the
/// rows with a list of its own lists it in this order, and the seeding
/// check, handed them, names the first a foreign row meets. Built from the
/// table at the first read, so a reader hands back a borrow of one
/// process-wide value and a pin is never rebuilt per consult; how many rows
/// there are is this slice's length and written nowhere (REG-1.26).
pub fn rows() -> &'static [Row] {
    static ROWS: LazyLock<Vec<Row>> = LazyLock::new(|| {
        SPELLINGS
            .iter()
            .map(|s| Row {
                of: s.of,
                address: commons_type(s.ordinals),
                type_value: s.type_value,
            })
            .collect()
    });
    &ROWS
}

/// The row whose address IS `a`, else `None` — by EQUALITY, never by
/// prefix: an address beneath a row or above one is no row of the table.
/// The difference is load-bearing where a reader sets the registry's rows
/// apart from the commons' others — the seeding check's domain (REG-1.31) —
/// since a foreign row placed under a kind is what the disjointness arm
/// exists to catch (REG-1.30), and a prefix test would set it aside unseen.
/// Equality, for its part, sets aside an address AT a row whoever spelled
/// it: right for a registry row spelled a second time (the insert door's
/// deposit class), and never for another allocator's row at that address,
/// which is REG-1.30's collision AT a row — so a hand filters through this
/// the second spellings of the registry's own rows alone
/// ([`crate::seeding_check`]).
pub fn row_at(a: &Address) -> Option<&'static Row> {
    rows().iter().find(|r| r.address == *a)
}

/// The REGISTRATION's kind — `1.1.0.1.0.1.0.3.54`; no deposit on the bare
/// ordinal (four readings).
pub fn t_registration() -> &'static Address {
    &Kind::Registration.row().address
}

/// The registration's REQUEST — `1.1.0.1.0.1.0.3.54.1`; a parent row, no
/// deposit on it (its kinds are rows beneath it).
pub fn t_request() -> &'static Address {
    &Subtype::Request.row().address
}

/// The request's FRESH kind — `1.1.0.1.0.1.0.3.54.1.1`.
pub fn t_request_fresh() -> &'static Address {
    &Subtype::RequestFresh.row().address
}

/// The request's BOARD-CARRIES-ON kind — `1.1.0.1.0.1.0.3.54.1.2`.
pub fn t_request_board_carries_on() -> &'static Address {
    &Subtype::RequestBoardCarriesOn.row().address
}

/// The registration's REPLY — `1.1.0.1.0.1.0.3.54.2`; a parent row, no
/// deposit on it (its answers are rows beneath it).
pub fn t_reply() -> &'static Address {
    &Subtype::Reply.row().address
}

/// The APPROVED answer — `1.1.0.1.0.1.0.3.54.2.1`.
pub fn t_reply_approved() -> &'static Address {
    &Subtype::ReplyApproved.row().address
}

/// The REFUSED answer — `1.1.0.1.0.1.0.3.54.2.2`.
pub fn t_reply_refused() -> &'static Address {
    &Subtype::ReplyRefused.row().address
}

/// The DENIED answer — `1.1.0.1.0.1.0.3.54.2.3`.
pub fn t_reply_denied() -> &'static Address {
    &Subtype::ReplyDenied.row().address
}

/// The VOUCH — `1.1.0.1.0.1.0.3.54.3`.
pub fn t_vouch() -> &'static Address {
    &Subtype::Vouch.row().address
}

/// The APPROVAL — `1.1.0.1.0.1.0.3.54.4`; link-alone.
pub fn t_approval() -> &'static Address {
    &Subtype::Approval.row().address
}

/// The BINDING — `1.1.0.1.0.1.0.3.55`; deposits ride the bare ordinal.
pub fn t_binding() -> &'static Address {
    &Kind::Binding.row().address
}

/// The ENDPOINT — `1.1.0.1.0.1.0.3.56`; deposits ride the bare ordinal, and
/// no subtype row stands under it (the org row retired).
pub fn t_endpoint() -> &'static Address {
    &Kind::Endpoint.row().address
}

/// The TAKEDOWN RECORD's kind — `1.1.0.1.0.1.0.3.57`; no deposit on the bare
/// ordinal (two readings).
pub fn t_takedown_record() -> &'static Address {
    &Kind::TakedownRecord.row().address
}

/// The takedown record's BASE reading — `1.1.0.1.0.1.0.3.57.1`.
pub fn t_takedown_base() -> &'static Address {
    &Subtype::TakedownBase.row().address
}

/// LIFTED — `1.1.0.1.0.1.0.3.57.2`; link-alone.
pub fn t_takedown_lifted() -> &'static Address {
    &Subtype::TakedownLifted.row().address
}

/// The POLICY LINK's kind — `1.1.0.1.0.1.0.3.58`; no deposit on the bare
/// ordinal (five readings).
pub fn t_policy_link() -> &'static Address {
    &Kind::PolicyLink.row().address
}

/// The policy link's OWN reading — `1.1.0.1.0.1.0.3.58.1`; link-alone, and
/// a row no rule writes (REG-1.15).
pub fn t_policy_link_own() -> &'static Address {
    &Subtype::PolicyLinkOwn.row().address
}

/// The DISAVOWAL — `1.1.0.1.0.1.0.3.58.2`.
pub fn t_disavowal() -> &'static Address {
    &Subtype::Disavowal.row().address
}

/// An expulsion's GROUND RECORD — `1.1.0.1.0.1.0.3.58.3`.
pub fn t_expulsion_ground() -> &'static Address {
    &Subtype::ExpulsionGround.row().address
}

/// A succession's GROUND RECORD — `1.1.0.1.0.1.0.3.58.4`.
pub fn t_succession_ground() -> &'static Address {
    &Subtype::SuccessionGround.row().address
}

/// The ORG-CHOSEN SUCCESSION POLICY — `1.1.0.1.0.1.0.3.58.5`.
pub fn t_succession_policy() -> &'static Address {
    &Subtype::SuccessionPolicy.row().address
}

/// `successor-of` — `1.1.0.1.0.1.0.3.59`; link-alone, the engine's own pin
/// held equal to this one.
pub fn t_successor_of() -> &'static Address {
    &Kind::SuccessorOf.row().address
}

// What only this module's privates can show: the registry range, its
// ordinal reader, and `row_at` against the type subspace's own prefix. The
// table's public face is tested from outside, in `tests/it/rows.rs`.
#[cfg(test)]
mod tests {
    use super::*;

    /// The count arm's bound: the registry range's ordinals (REG-1.25),
    /// never the reserve's name (REG-1.24) — one ordinal a kind, as the list
    /// stands, the count read off the list.
    #[test]
    fn the_registry_range_is_the_ordinals_the_kinds_take() {
        assert_eq!(REGISTRY_RANGE, 54..=59);
        assert_eq!(REGISTRY_RANGE.count(), Kind::ALL.len(), "a bare ordinal a kind");
    }

    /// A bare ordinal of the registry range in the commons type subspace
    /// answers itself; `3.53` — inside the reserve commons-map names and
    /// outside the registry range (REG-1.24) — an ordinal past the range, a
    /// row beneath a kind, a row beneath a parent row, a deeper address
    /// ending in a range ordinal and that ordinal in another subspace of the
    /// ghost home document answer none.
    #[test]
    fn the_registry_range_ordinal_is_read_off_a_bare_row_inside_the_range_alone() {
        assert_eq!(registry_range_ordinal(&commons_type(&[54])), Some(54));
        assert_eq!(registry_range_ordinal(&commons_type(&[55])), Some(55));
        assert_eq!(registry_range_ordinal(&commons_type(&[59])), Some(59));
        assert_eq!(registry_range_ordinal(&commons_type(&[53])), None);
        assert_eq!(registry_range_ordinal(&commons_type(&[60])), None);
        assert_eq!(registry_range_ordinal(&commons_type(&[57, 1])), None);
        assert_eq!(registry_range_ordinal(&commons_type(&[54, 1, 1])), None);
        assert_eq!(registry_range_ordinal(&commons_type(&[55, 55])), None);
        let in_subspace_1 = [1u32, 1, 0, 1, 0, 1, 0, 1, 55].map(Nat::from);
        let in_subspace_1 =
            validate(Tumbler::new(in_subspace_1).expect("nonempty")).expect("T4-valid");
        assert_eq!(registry_range_ordinal(&in_subspace_1), None);
    }

    /// The row AT an address is answered by equality: every row's own
    /// address answers that row, held; an address beneath a row, the
    /// subspace above every row and a foreign row answer none.
    #[test]
    fn row_at_answers_a_rows_own_address_alone() {
        for r in rows() {
            let found = row_at(&r.address);
            assert!(found.is_some_and(|f| std::ptr::eq(f, r)), "{}", r.address);
        }
        let subspace = Tumbler::new(COMMONS_TYPE_PREFIX.map(Nat::from)).expect("nonempty");
        let subspace = validate(subspace).expect("T4-valid");
        let beneath =
            [commons_type(&[58, 6]), commons_type(&[57, 1, 1]), commons_type(&[54, 1, 3])];
        for a in beneath.into_iter().chain([subspace, commons_type(&[12]), commons_type(&[53])]) {
            assert_eq!(row_at(&a), None, "{a}");
        }
    }
}
