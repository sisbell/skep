//! M3's journal delta and the identity type it names (§Core data model):
//! [`PrincipalId`] with its two fixed ids, and [`M3Rec`] — the records M3
//! stages through M2's `transact` and the fold [`M3State::apply_m3`]
//! consumes — with the two payloads whose fields are private, `Allocate`'s
//! [`Allocation`] and `RegisterPrincipal`'s [`Principal`], and the two field
//! doors a record re-enters through off the journal, private here because
//! the record's own decode is their one caller. The variant order is the
//! journal format, as `M3State`'s field order is the checkpoint's: a variant
//! is appended, never inserted or reordered. No other crate constructs a
//! record of its own choosing except by decoding bytes, and none edits one
//! past its doors — [`M3Rec`] states the seals, and what a decoded record
//! costs; the `test-hooks` feature compiles in three constructors for the
//! test suites that seed M3 state through the fold. What a caller staging a
//! mint's record owes is on [`M3Rec::Allocate`]; the `published` a
//! non-document record carries, `NO_PUBLICATION_STATE`, is its producers'
//! word and is declared beside them, in `state`.
//!
//! [`M3State::apply_m3`]: crate::M3State::apply_m3

use serde::{Deserialize, Deserializer, Serialize};
use skep_address::{Address, Level};

/// Opaque external identity, supplied by M10/session. `delegate` enforces
/// id-injectivity ([`crate::DelegateError::DuplicateId`]) ⇒ one id ↦ one
/// principal, which keeps [`M3State::principal_prefix`] and the ω-auth gate
/// single-valued (§6).
///
/// The order is the underlying numeral's and carries no ownership meaning —
/// ownership is decided by prefix length, never by id (§5). It is here
/// because an id is a map key and a sort key: the `id → prefix` reverse index
/// [`M3State`] names as a recomputable hint wants a `BTreeMap`, whose
/// iteration order is deterministic where a hashed one's is the process's
/// hash seed, and no downstream crate can add the impl.
///
/// [`M3State`]: crate::M3State
/// [`M3State::principal_prefix`]: crate::M3State::principal_prefix
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct PrincipalId(pub u64);

/// π₀'s fixed id (genesis Σ₀, O14); the ω-auth gate keys on it, so M10 binds
/// the bootstrap session to it. `delegate`'s id-freshness gate then prevents
/// any later principal from re-claiming id 0 (§7).
pub const BOOTSTRAP_PRINCIPAL: PrincipalId = PrincipalId(0);

/// The SYSTEM ACCOUNT's fixed principal (PUB-6.65, RES-304): the id genesis
/// seats at [`system_account`] `1.1.0.1`, the account the board's own daemon
/// writes the published head document into. Never `0` (that is
/// [`BOOTSTRAP_PRINCIPAL`]) and a reserved sentinel no client can seat: the
/// account holds no key and can never enrol one (AUTH-6.19's cell — a keyless
/// account answers empty lists), and [`crate::Namespace::delegate`]'s
/// id-freshness gate refuses this id `DuplicateId` because genesis has already
/// registered it (§6/§7). So no principal but the one genesis seats ever bears
/// it, and it can act only in-process, never over a session.
///
/// The VALUE is a conspicuous reserved sentinel — `9 × 10^15`, well below the
/// wire's `2^53 − 1` exact-integer cap (AUTH-5.20) yet far above any ordinary
/// delegation — so a client's attempt to re-seat it PARSES and reaches the
/// freshness gate, refused `duplicate_id` (the "not fresh" refusal PUB-6.65
/// names), rather than being turned away earlier as an unrepresentable number.
///
/// [`system_account`]: crate::system_account
pub const SYSTEM_PRINCIPAL: PrincipalId = PrincipalId(9_000_000_000_000_000);

/// M3's journal deltas — lifted to `W::Record` via the engine's `From<M3Rec>`
/// impl (the write-side mirror of [`crate::HasM3`]) and folded by
/// [`M3State::apply_m3`]. Every address payload is an [`Address`], so
/// T4-validity is carried by the value: checked once where the record is
/// built, and re-checked on the way back off the journal by M1's validating
/// `Deserialize`. A record still journals as a bare, flat tumbler, exactly as
/// the data model prescribes. One `Allocate` variant suffices for every minted
/// address (entity, content, link) because the frontier map is uniform; the
/// level distinction is recovered at *query* time from the address's own
/// level.
///
/// Two fields owe a fact T4-validity does not carry, and each checks it in a
/// decoder on the field itself, after M1's: an `Allocate` address extends a
/// parent (`parented_address`), and a `RegisterPrincipal` prefix is
/// account-tier (`account_tier_prefix`). A record lacking either is refused
/// at decode, as M2's ordinary decode failure. Both are facts about one
/// field, so they ride on the field and `Deserialize` is derived — on this
/// enum, and on [`Allocation`] and [`Principal`] for the two variants'
/// payloads: a variant added here decodes with no second edit, and the
/// journal and checkpoint encoding is the types' own.
///
/// THE SEALS. The TYPE is `#[non_exhaustive]`, so a foreign `match` carries
/// a `_` arm and a variant appended at the end costs it no build. `Allocate`
/// and `RegisterPrincipal` each carry a payload whose fields are private,
/// [`Allocation`] and [`Principal`], because each carries one of those two
/// door facts and no type holds either: no crate but this one builds either
/// payload by literal or writes its fields, so a fact a door established
/// stands for as long as the record does, wherever it is pushed. A seal on
/// the variant alone would not do: Rust has no private enum-variant fields,
/// so every crate that can match a struct variant can bind its fields
/// through `&mut` — and every M5 and M7 write composite holds a minted
/// `Allocate` between the mint and the push, while any crate can hold a seat
/// it decoded. `RegisterNode`'s one door fact is T4-validity, which the
/// [`Address`] it carries holds by type, so it needs no payload: the variant
/// is `#[non_exhaustive]`, as M5's `M5Rec` and M7's `LinkRec` variants are,
/// so no crate but this one builds one by struct literal, and a crate that
/// rewrites a decoded one's address reaches no address the decode could not
/// have carried.
///
/// So the mints, the four ops and genesis are this record's producers: a
/// composite in another crate stages the record a mint returned exactly as
/// the mint built it, and the four public mints are the only constructors a
/// foreign crate can NAME that choose what a record carries — it can name
/// `M3Rec::Allocate` and `M3Rec::RegisterPrincipal` too, but those only
/// re-wrap a payload it already holds, as the second pair's twin below does.
/// The one other path it can REACH is decoding: the record derives
/// `Deserialize`, as M2's journal requires, so bytes a foreign crate wrote
/// decode into one, through the field doors. Such a record holds every door
/// fact and nothing more. What its producer owes — the next ordinal, the
/// seat beside an account, a fresh id — no door can check, so a crate that
/// decodes a record and pushes it is a producer, owes what
/// [`M3Rec::Allocate`] and [`M3Rec::RegisterPrincipal`] state, and is
/// covered by none of the fold's guarantees where it falls short. What the
/// doors and the seals settle together is the journal: in a build that
/// compiles no test, every record any crate can push passes the doors it
/// will be read back through, so no commit leaves an M3 frame its own replay
/// refuses. None of the seals costs a reader anything: a foreign crate lifts
/// the record whole, reads the two payloads through their accessors
/// ([`Allocation::addr`], [`Allocation::published`], [`Principal::prefix`],
/// [`Principal::id`]) and `RegisterNode`'s field through a pattern with
/// `..`, and this crate's fold matches and destructures freely. The suites
/// that seed M3 state through the fold — states no op produces among them —
/// build their records with the `test-hooks` constructors, which a build
/// that compiles no test does not contain.
///
/// The seals as a foreign crate meets them, each a pair: the twin compiles,
/// and the refusal differs from it in one place — a write to an allocation's
/// field, an allocation built by literal, a write to a principal's field, a
/// node built by struct literal, a `match` over every variant with no `_`
/// arm. A bare `compile_fail` is satisfied by ANY compile error, so the twin
/// is what keeps each refusal a statement about its seal. (The error codes
/// are checked on nightly only.)
///
/// ```
/// use skep_namespace::{system_account, M3Rec, M3State};
/// let (addr, mut rec) = M3State::genesis()
///     .mint_document(&system_account(), true)
///     .expect("the system account mints");
/// if let M3Rec::Allocate(allocation) = &mut rec {
///     assert_eq!(*allocation.addr(), addr);
/// }
/// ```
/// ```compile_fail,E0616
/// use skep_namespace::{system_account, M3Rec, M3State};
/// let (addr, mut rec) = M3State::genesis()
///     .mint_document(&system_account(), true)
///     .expect("the system account mints");
/// if let M3Rec::Allocate(allocation) = &mut rec {
///     allocation.addr = addr;
/// }
/// ```
/// ```
/// use skep_namespace::{system_account, Allocation, M3Rec, M3State};
/// let (addr, minted) = M3State::genesis()
///     .mint_document(&system_account(), true)
///     .expect("the system account mints");
/// let M3Rec::Allocate(allocation) = minted else {
///     unreachable!("a mint returns an Allocate")
/// };
/// let allocation: Allocation = allocation;
/// let rec = M3Rec::Allocate(allocation);
/// assert!(matches!(&rec, M3Rec::Allocate(allocation) if *allocation.addr() == addr));
/// ```
/// ```compile_fail,E0451
/// use skep_namespace::{system_account, Allocation, M3Rec, M3State};
/// let (addr, minted) = M3State::genesis()
///     .mint_document(&system_account(), true)
///     .expect("the system account mints");
/// let M3Rec::Allocate(allocation) = minted else {
///     unreachable!("a mint returns an Allocate")
/// };
/// let allocation: Allocation = Allocation { addr: addr.clone(), published: true };
/// let rec = M3Rec::Allocate(allocation);
/// assert!(matches!(&rec, M3Rec::Allocate(allocation) if *allocation.addr() == addr));
/// ```
/// ```
/// use skep_namespace::{system_node, M3Rec};
/// fn reach(rec: &mut M3Rec) {
///     if let M3Rec::RegisterPrincipal(principal) = rec {
///         assert_ne!(*principal.prefix(), system_node());
///     }
/// }
/// ```
/// ```compile_fail,E0616
/// use skep_namespace::{system_node, M3Rec};
/// fn reach(rec: &mut M3Rec) {
///     if let M3Rec::RegisterPrincipal(principal) = rec {
///         principal.prefix = system_node();
///     }
/// }
/// ```
/// ```
/// use skep_namespace::{system_account, system_node, M3Rec, M3State};
/// let addr = system_node();
/// let (_, rec) = M3State::genesis()
///     .mint_document(&system_account(), true)
///     .expect("the system account mints");
/// assert!(!matches!(&rec, M3Rec::RegisterNode { addr: node, .. } if *node == addr));
/// ```
/// ```compile_fail,E0639
/// use skep_namespace::{system_account, system_node, M3Rec, M3State};
/// let addr = system_node();
/// let rec = M3Rec::RegisterNode { addr: addr.clone() };
/// assert!(!matches!(&rec, M3Rec::RegisterNode { addr: node, .. } if *node == addr));
/// ```
/// ```
/// use skep_namespace::{system_account, M3Rec, M3State};
/// let (_, rec) = M3State::genesis()
///     .mint_document(&system_account(), true)
///     .expect("the system account mints");
/// let allocates = match rec {
///     M3Rec::Allocate(_) => true,
///     M3Rec::RegisterNode { .. } | M3Rec::RegisterPrincipal(_) => false,
///     _ => false,
/// };
/// assert!(allocates);
/// ```
/// ```compile_fail,E0004
/// use skep_namespace::{system_account, M3Rec, M3State};
/// let (_, rec) = M3State::genesis()
///     .mint_document(&system_account(), true)
///     .expect("the system account mints");
/// let allocates = match rec {
///     M3Rec::Allocate(_) => true,
///     M3Rec::RegisterNode { .. } | M3Rec::RegisterPrincipal(_) => false,
/// };
/// assert!(allocates);
/// ```
///
/// [`M3State::apply_m3`]: crate::M3State::apply_m3
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum M3Rec {
    /// A mint's COMMIT HALF: advance the frontier of the chain its address
    /// ([`Allocation::addr`]) lies on (§1) — this record is the only thing
    /// that moves a frontier — which is exactly the chain whose `*_lock_key`
    /// its mint pairs with: frontier key and lock key are one key.
    ///
    /// WHERE IT MAY BE STAGED — the caller's half of every mint, and the one
    /// obligation M3 cannot check, since the record carries an address and
    /// not the state its mint read: in the transaction whose WORKING state
    /// the mint was called on, under the mint's paired `*_lock_key`, before
    /// any other record advances the same chain. Its address is `c_{m+1}` of
    /// THAT state, and only there is the record inside
    /// [`M3State::apply_m3`]'s totality domain. Dropped, it leaves the
    /// frontier where it stood, and the next mint on the chain hands out the
    /// SAME address with nothing to say so — that mint's record is
    /// legitimately `m + 1`. Staged anywhere else, it is STALE: a peek's
    /// record staged in a later transaction, a mint called on `stg.base()`
    /// after another on its chain was staged, or two mints on one chain
    /// before either record is pushed. Once another mint has landed on the
    /// chain, a stale record issues that address a second time, and once two
    /// have, it also sets the frontier back to its own ordinal, so the later
    /// addresses read unallocated and are minted again. Only the fold's
    /// contiguity `debug_assert` refuses a stale record; a release build
    /// folds it, and [`M3State::is_allocated`]'s permanent `true` no longer
    /// holds on its chain.
    ///
    /// An ACCOUNT's `Allocate` owes one record more, and the fold does not
    /// check it: its principal's [`M3Rec::RegisterPrincipal`], in the same
    /// transaction (O17b — an account's seat is its allocation; that record
    /// states the coupling's other half). `delegate`, the only op that
    /// allocates an account, stages both.
    ///
    /// Its bit, [`Allocation::published`], is the RESOLVED publication state
    /// of a minted DOCUMENT (PUB-7.8, PUB-7.10, PUB-8.18): every
    /// document-minting record journals the bit its caller resolved — never
    /// the caller's three-valued flag, so replay reconstructs the world that
    /// committed and not a re-derivation from the op's arguments — and
    /// [`M3State::apply_m3`] folds it into the publication map for a
    /// Document-tier address (a version is a document too). IMMUTABLE after
    /// mint: no op changes it — there is no publication transition in either
    /// direction, and the publish shot mints a new member rather than
    /// changing one (PUB-1.9, PUB-1.68) — and no LATER record changes it
    /// either: the fold writes the entry only where none is held, so a second
    /// `Allocate` naming a registered document leaves its bit alone. Outside
    /// the document tier — an account, a content or link element —
    /// publication is not a property of the address at all (PUB-1.68: one
    /// bit per DOCUMENT); those mints stamp `NO_PUBLICATION_STATE` (`false`)
    /// and the fold does not read it.
    /// NON-OPTIONAL by design (PUB-7.8) — no `Option`, no `#[serde(default)]`:
    /// a frame written before the bit existed ends where the bit should begin,
    /// and that end-of-input is the refusal. M2 then replays from an older
    /// start point or refuses to serve (PUB-7.9); the frame is never read as
    /// private or as published by a default it never carried (PUB-1.2: no
    /// grandfather clause).
    ///
    /// [`M3State::apply_m3`]: crate::M3State::apply_m3
    /// [`M3State::is_allocated`]: crate::M3State::is_allocated
    Allocate(Allocation),
    /// External node admission (ASN-0047 NodeBaptism; §7).
    #[non_exhaustive]
    RegisterNode { addr: Address },
    /// Delegation's principal half (§6): the [`Principal`] it seats. Written
    /// once: the fold leaves an already-seated prefix's principal alone
    /// (O12/O13), so no later record replaces a seat.
    ///
    /// ITS PRODUCER'S HALF — two clauses, and the fold checks neither: stage
    /// it in the transaction that stages its prefix's own `Allocate` (O17b;
    /// ASN-0042's PrefixBaptismCoupling — an account's seat is its
    /// allocation), and under an `id` no principal carries. `delegate`, its
    /// one producer on the journal, keeps both: its `DuplicateId` gate
    /// refuses a carried id, and it stages the seat beside the `Allocate` its
    /// account mint returned. Genesis folds its one seat beside its account's
    /// `Allocate`, under an id no root carries. Staged without the
    /// allocation, the record seats an account no chain holds, and the
    /// owner-of-address read (AUTH-6.37) then calls that account allocated;
    /// staged under a carried id, it makes [`M3State::principal_prefix`]
    /// arbitrary. A producer this crate adds owes both clauses, and no other
    /// crate can construct one: its payload's fields are private
    /// ([`Principal`]), and the `test-hooks` constructor that builds one
    /// unchecked is default-off, turned on only on dev-dependency lines. A
    /// crate that decodes one from bytes it wrote and pushes it is a producer
    /// all the same, and owes both clauses with only the prefix door between
    /// it and the fold — a door its payload's private fields keep standing.
    ///
    /// [`M3State::principal_prefix`]: crate::M3State::principal_prefix
    RegisterPrincipal(Principal),
}

/// What an [`M3Rec::Allocate`] carries — the address a mint issued and the
/// publication bit stamped on it — behind private fields, so the record a
/// mint returns is the record the fold receives: no crate but this one builds
/// an `Allocation` by literal or writes one, and another crate holds one
/// only as a mint returned it or as it decoded it, through `addr`'s at-rest
/// door and no other check ([`M3Rec`] states what a decoded record costs). A
/// struct variant cannot hold that line, since Rust has no private
/// enum-variant fields: a crate that can match `Allocate { addr, .. }` can
/// bind `addr` through `&mut`, `#[non_exhaustive]` or not. Read through
/// [`Allocation::addr`] and [`Allocation::published`].
///
/// Its bytes are a struct variant's: bincode writes a newtype variant as its
/// index and then its payload, and a struct as its fields in order, which is
/// exactly how it writes a struct variant `Allocate { addr, published }` —
/// `tests/it/recovery.rs` pins the bytes against a raw struct-variant twin. So
/// the field order is journal format, as the variant order is: a field is
/// appended, never inserted or reordered. `addr` re-enters through its at-rest
/// door (`parented_address`), and `published` takes no default (PUB-7.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    /// The address the mint issued: `c_{m+1}` of the chain it lies on.
    #[serde(deserialize_with = "parented_address")]
    pub(crate) addr: Address,
    /// The bit the mint stamped ([`M3Rec::Allocate`] states its rule).
    pub(crate) published: bool,
}

impl Allocation {
    /// The address the mint issued.
    pub fn addr(&self) -> &Address {
        &self.addr
    }

    /// The publication bit the record journals: the RESOLVED state of a
    /// Document-tier [`Allocation::addr`] (PUB-8.18), and for any other tier
    /// the `NO_PUBLICATION_STATE` absence the fold never reads.
    pub fn published(&self) -> bool {
        self.published
    }
}

/// What an [`M3Rec::RegisterPrincipal`] carries — the prefix a principal is
/// seated at, ASN-0042's `pfx(π)`, and the id it bears — behind private
/// fields, for the reason [`Allocation`]'s are. The prefix owes the one fact
/// a seat needs that no type carries, the ACCOUNT TIER (O15(iii), narrowed),
/// and its at-rest door (`account_tier_prefix`) checks it at decode. A field
/// another crate could write would let a decoded seat be rewritten past that
/// door — at node tier, into a seat ω answers as the owner of everything
/// under the node no deeper account principal covers — and the record,
/// journaled as rewritten, would be refused by that same door at the next
/// open, which M2 answers with its corruption halt, never a drop. So no
/// crate but this one builds a `Principal` by literal or writes one, and in
/// a build that compiles no test every `Principal` any crate holds carries
/// an account-tier prefix: `delegate` stages only such a prefix, genesis
/// folds the system account's, and a decoded one passed the door. Read
/// through [`Principal::prefix`] and [`Principal::id`].
///
/// Its bytes are a struct variant's, as [`Allocation`]'s are: bincode writes
/// a newtype variant as its index and then its payload, and a struct as its
/// fields in order, which is exactly how it writes a struct variant
/// `RegisterPrincipal { prefix, id }` — `tests/it/recovery.rs` pins the bytes
/// against a raw struct-variant twin. So the field order is journal format,
/// as the variant order is: a field is appended, never inserted or
/// reordered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// The prefix the principal is seated at: account-tier.
    #[serde(deserialize_with = "account_tier_prefix")]
    pub(crate) prefix: Address,
    /// The id the principal bears.
    pub(crate) id: PrincipalId,
}

impl Principal {
    /// The prefix the principal is seated at, `pfx(π)` — account-tier in a
    /// build that compiles no test.
    pub fn prefix(&self) -> &Address {
        &self.prefix
    }

    /// The id the principal bears.
    pub fn id(&self) -> PrincipalId {
        self.id
    }
}

/// The record's three TEST constructors (`test-hooks`, default off): the one
/// way a crate other than this one constructs an `M3Rec` of its own choosing
/// without decoding bytes, for the suites that seed M3 state through the
/// fold — states no op produces among them, an account allocated without its
/// seat, a seat below the account tier. Each builds its variant as given and
/// checks nothing, as a struct literal inside this crate does. The feature
/// is turned on only on dev-dependency lines, so a build that compiles no
/// test holds none of them, and a production path that reached for one
/// would not compile.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
impl M3Rec {
    /// `Allocate(Allocation { addr, published })`.
    pub fn allocate(addr: Address, published: bool) -> M3Rec {
        M3Rec::Allocate(Allocation { addr, published })
    }

    /// `RegisterNode { addr }`.
    pub fn register_node(addr: Address) -> M3Rec {
        M3Rec::RegisterNode { addr }
    }

    /// `RegisterPrincipal(Principal { prefix, id })`.
    pub fn register_principal(prefix: Address, id: PrincipalId) -> M3Rec {
        M3Rec::RegisterPrincipal(Principal { prefix, id })
    }
}

/// `Allocation.addr`'s at-rest door: M1's validating decode, then the standing
/// fact [`M3State::apply_m3`]'s `namespace_of` `expect` rests on, and which
/// T4-validity does NOT carry: a minted address extends a parent. `[7]` is
/// T4-valid, so M1's door passes it, and a parentless `Allocate` reaching the
/// fold would panic the applier — at replay too, on every subsequent open.
/// For a T4-valid address `parent(a).is_some()` ⟺ `#a ≥ 2` (M1's `parent` is
/// `None` only for a single-component node), so the check is one length
/// compare, and it turns a permanent applier panic into M2's ordinary decode
/// failure.
///
/// [`M3State::apply_m3`]: crate::M3State::apply_m3
fn parented_address<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
    let addr = Address::deserialize(d)?;
    if addr.tumbler().len() < 2 {
        return Err(serde::de::Error::custom(
            "an Allocate address extends a parent (≥ 2 components)",
        ));
    }
    Ok(addr)
}

/// `Principal.prefix`'s at-rest door: M1's validating decode, then the fact
/// a seat needs whose absence fails OPEN — the prefix is account-tier. The
/// field is private ([`Principal`]), so the fact this door establishes
/// stands for as long as the record does: no holder rewrites a decoded
/// prefix past it.
///
/// `delegate` is its sole producer on the journal and its hoisted
/// `NotAccountTier` gate stages nothing else, so the door refuses nothing M3
/// has ever journaled — genesis's node-tier π₀ seat is world state, passed to
/// `Kernel::open`, not a record, and the one seat genesis folds,
/// `SYSTEM_PRINCIPAL`'s, is account-tier. The tier matters because ω's O1a
/// filter ADMITS node tier (it must, for π₀): a node-tier seat arriving on
/// the journal would make its carrier the effective owner of everything under
/// that node no deeper account principal covers — including the unallocated
/// subtree, so it could seat that node's first account, the operator seat
/// `register_node`'s postcondition leaves to whoever owns the covering
/// prefix. A below-tier seat is refused by every reader of Π already; this is
/// the shape that is not.
///
/// The door is therefore tighter than O1a, and deliberately: a STATE-level
/// door could not be, since genesis's seat is node-tier, so [`M3State`]'s
/// bare-derive checkpoint path keeps that exposure and ω's tier filter
/// (`omega`) is not removable. An op that ever seats a principal at a node
/// prefix changes this door first.
///
/// A field door carries facts about its own field and no others. The standing
/// property `RegisterPrincipal` would want besides — id-injectivity across Π
/// — is not one: it is a claim about the principal registry the record is
/// about to enter, which no decoder holding a single frame can settle. That
/// invariant has one owner, `delegate`'s `DuplicateId` gate, and this door
/// does not share it.
///
/// [`M3State`]: crate::M3State
fn account_tier_prefix<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
    let prefix = Address::deserialize(d)?;
    if prefix.level() != Level::Account {
        return Err(serde::de::Error::custom(
            "a RegisterPrincipal prefix is account-tier (delegate's O15(iii) gate)",
        ));
    }
    Ok(prefix)
}
