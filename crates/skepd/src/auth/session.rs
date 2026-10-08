//! The session layer (AUTH part 04): nonces and the challenge store, the
//! session token and store, per-request resolution, and the handshake.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rand_core::CryptoRng;
use serde_json::Value;
use skep_febe::SessionId;
use skep_identity::{
    framed, Fingerprint, HasIdentity, HybridBlob, IdentityState, KeySet, PublicKey, SESSION_TAG,
    SESSION_TAG_V2, SIG_ALGS,
};
use skep_namespace::{PrincipalId, BOOTSTRAP_PRINCIPAL};
use skep_util::json::{hex_string, parse_lower_hex};

use super::{bare_origins, signed_origins, AuthConfig, Mode, Origin};
use crate::codec::check_keys;
use crate::World;
use skep_address::{parent, Address, Level};
use skep_namespace::HasM3;

/// The challenge TTL — a PIN, not a knob: `ttl_ms` on the wire is a byte
/// pin of this constant (AUTH-4.12).
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// [`CHALLENGE_TTL`] as the WIRE publishes it — `ttl_ms` on `GET /challenge`
/// (AUTH-6.1), and a byte pin of that constant, derived beside it as
/// [`SESSION_TOKEN_BYTES`] is derived from its own: the wire reports the
/// number the store uses or the build fails. A literal at the route would be
/// a second spelling of it, free to drift in silence on the one field whose
/// whole contract is that it does not, and a runtime conversion there would
/// check per request what is knowable once.
pub(crate) const CHALLENGE_TTL_MS: u64 = CHALLENGE_TTL.as_millis() as u64;

/// The cast above is lossless — asserted at COMPILE time, and this is the
/// whole proof rather than the shorter "the TTL is seconds", which is true
/// of `from_secs(u64::MAX)` too.
const _: () = assert!(
    CHALLENGE_TTL_MS as u128 == CHALLENGE_TTL.as_millis(),
    "the challenge TTL must be publishable as a u64 count of milliseconds"
);

/// Session-token unpredictability (AUTH-4.13): at least this many bits per
/// token from a `CryptoRng` — never a per-process prefix plus a counter.
const SESSION_TOKEN_BITS: usize = 128;

/// The floor met exactly, as the byte width [`Token`] holds and
/// [`Sessions::open`] draws per token.
const SESSION_TOKEN_BYTES: usize = SESSION_TOKEN_BITS / 8;

// ── Peer ─────────────────────────────────────────────────────────────────

/// The TCP peer's loopback-ness ALONE, no address payload (AUTH-4.14).
/// `X-Forwarded-*` is deliberately ignored — the declined demote-only
/// reading is recorded there and must not be re-derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Peer {
    Loopback,
    Remote,
}

impl Peer {
    /// The class of a peer at `ip` (AUTH-4.14): `Loopback` for an address
    /// `IpAddr::is_loopback` admits — `127.0.0.0/8` and `::1` both, which is
    /// the whole of it — and `Remote` otherwise.
    ///
    /// Here rather than at the accept path because this type is PUBLIC and a
    /// caller routing over its own transport builds one
    /// ([`crate::HttpRequest`]): the bare bind is the one privilege this
    /// daemon grants without a signature, so a `Loopback` for a socket that
    /// is not one hands that privilege to the network. The rule is four
    /// tokens and both near-misses are unsafe in a direction the type can
    /// close — `ip == Ipv4Addr::LOCALHOST` denies a legitimate `::1` bind,
    /// and any host-reachability notion admits a LAN peer — so the daemon's
    /// own answer is offered rather than described.
    ///
    /// An `IpAddr` and not a `SocketAddr`: the port is not read, and
    /// `SocketAddr::ip` is what a caller holding one calls. A caller whose
    /// transport carries no address at all — a Unix socket — names the
    /// variant it means.
    pub fn of(ip: IpAddr) -> Peer {
        if ip.is_loopback() {
            Peer::Loopback
        } else {
            Peer::Remote
        }
    }

    fn is_loopback(self) -> bool {
        matches!(self, Peer::Loopback)
    }
}

// ── Nonce & Challenges (AUTH-4.15–4.21) ──────────────────────────────────

/// A handshake nonce; wire form 64 LOWERCASE hex (AUTH-4.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Nonce([u8; 32]);

impl Nonce {
    /// 64 lowercase hex, always.
    // AUTH-4.15 pins this exact declaration — `to_hex(&self)` — and the
    // type being `Copy` is what trips the by-value convention lint.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex(&self) -> String {
        hex_string(&self.0)
    }

    /// ONLY 64 lowercase hex — deliberately narrower than
    /// `Fingerprint::parse_hex` (AUTH-4.16): an uppercase nonce is a 400
    /// syntax fault whose nonce SURVIVES, never a burned 401.
    pub fn parse_hex(s: &str) -> Option<Nonce> {
        parse_lower_hex(s).map(Nonce)
    }
}

/// The challenge store (AUTH-4.19): a map plus a FIFO of insertion order
/// behind the store's OWN lock; the exclusion never spans a verify. A
/// burned nonce retains NEITHER entry.
pub(crate) struct Challenges {
    inner: parking_lot::Mutex<ChallengeInner>,
    cap: usize,
}

struct ChallengeInner {
    map: HashMap<Nonce, (PrincipalId, Instant)>,
    order: VecDeque<Nonce>,
}

impl Challenges {
    pub fn new(cap: usize) -> Challenges {
        Challenges {
            inner: parking_lot::Mutex::new(ChallengeInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            cap,
        }
    }

    /// Issue a nonce for ANY principal (nothing is secret); evict the
    /// oldest past the cap (AUTH-4.20).
    pub fn issue(
        &self,
        principal: PrincipalId,
        now: Instant,
        rng: &mut impl CryptoRng,
    ) -> Nonce {
        let mut raw = [0u8; 32];
        rng.fill_bytes(&mut raw);
        let nonce = Nonce(raw);
        let mut inner = self.inner.lock();
        inner.map.insert(nonce, (principal, now + CHALLENGE_TTL));
        inner.order.push_back(nonce);
        while inner.order.len() > self.cap {
            if let Some(old) = inner.order.pop_front() {
                inner.map.remove(&old);
            }
        }
        nonce
    }

    /// SINGLE-USE: the burn (AUTH-4.21) — removes the entry from BOTH
    /// structures whether or not it VALIDATES (a wrong principal and an
    /// expired entry both burn); true iff present, unexpired, and issued for
    /// `principal`.
    ///
    /// A nonce the MAP never held is absent from the QUEUE too, so the
    /// whole-queue sweep below is a no-op in exactly that case and is
    /// skipped: [`Challenges::issue`] inserts into both, this removes from
    /// both, and the eviction pops from both, so membership agrees. (Two
    /// draws colliding — 2⁻²⁵⁶ — would leave `order` a stale member the
    /// eviction later pops against an absent map entry, which costs one slot
    /// of the cap and nothing else.)
    ///
    /// THE MISS is the case a stranger drives, which is why the skip is
    /// worth its sentence: `POST /session` reaches here with ANY 64-hex
    /// nonce, past the origin-set test and nothing else — no key set is read
    /// and no signature verified until step 5 — so an unswept miss would buy
    /// a [`super::MAX_LIVE_NONCES`]-element scan of 32-byte nonces per
    /// unauthenticated request, under this store's ONE mutex, queueing every
    /// `GET /challenge` behind it.
    pub fn burn(&self, nonce: &Nonce, principal: PrincipalId, now: Instant) -> bool {
        let mut inner = self.inner.lock();
        let Some((issued_to, expires)) = inner.map.remove(nonce) else { return false };
        inner.order.retain(|n| n != nonce);
        issued_to == principal && now < expires
    }
}

// ── Token & Sessions (AUTH-4.17, AUTH-4.23–4.25) ─────────────────────────

/// The opaque session token: 128 bits of fresh CSPRNG output, wire form 32
/// lowercase hex. `parse` admits ONLY what `to_wire` emits and the pair is
/// injective (AUTH-4.17). Compared exactly, never logged.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Token([u8; SESSION_TOKEN_BYTES]);

/// The bytes are the credential, so they do not appear here: this type's
/// contract is "compared exactly, never logged", and a DERIVED `Debug` is
/// what turns that into "never logged, except through `{:?}`". The same
/// treatment [`crate::HttpRequest`] gives the token it carries, and the
/// reason [`Sessions`] derives no `Debug` at all.
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

impl Token {
    pub fn to_wire(&self) -> String {
        hex_string(&self.0)
    }

    /// ONLY 32 lowercase hex; a value this refuses is NO token
    /// (AUTH-4.18) — it resolves `Guest(NoToken)`, nothing to close.
    pub fn parse(s: &str) -> Option<Token> {
        parse_lower_hex(s).map(Token)
    }
}

/// A session's SCOPE (AUTH-4.39; RES-63): the LIMIT a signed session may
/// declare for itself at its opening, inside its signed bytes. A `Content`
/// session reads, holds its draft visibility, writes content, publishes,
/// grants and closes exactly as a `Full` one does, and cannot deposit, retire
/// or claim a credential. It only narrows: a signed body with no `scope` is
/// `Full`, and the BARE arm is scope-less — a bare binding is `Full` in shape
/// and keeps every rule it has.
///
/// Not a grade: the key that opened the session is not consulted, so an
/// anchor key's content session is content-limited all the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Full,
    Content,
}

impl Scope {
    /// The ONE value the body's `scope` member takes (AUTH-6.2) — the JSON
    /// string, no other value, type or case; there is no `full` spelling
    /// (absence IS full). Also the bytes a scoped body SIGNS (AUTH-6.4): the
    /// parse admits exactly this string, which is what lets
    /// [`session_payload`] frame it from the value and still frame "the
    /// body's OWN bytes".
    const CONTENT: &'static str = "content";
}

/// One live session's binding: the M10 session, the named principal, the
/// fingerprint of the enrolled key that established it (`None` = a bare
/// bind, which signs nothing), and the scope it declared.
///
/// `scope` is set ONCE, at the open, from the VERIFIED body — it is
/// [`handshake`]'s answer, never the request's — and held for the binding's
/// lifetime. It is READ at exactly one place, the precheck's slot (6), on
/// every write the dispatch routes there ([`super::policy::precheck`]), and
/// NOWHERE ELSE: [`resolve`], the death sequence, `/session/close`, the
/// reads' draft visibility and [`SessionBinding::testimony`] are scope-blind,
/// and `/health.auth` publishes nothing of it. It is in no record, journal,
/// sidecar or fold: it dies with its binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionBinding {
    pub sid: SessionId,
    pub principal: PrincipalId,
    pub signer: Option<Fingerprint>,
    pub scope: Scope,
}

impl SessionBinding {
    /// The AUTH testimony of a write this session commits (AUTH-4.48): the
    /// establishing key's fingerprint hex, or `"bare"` for a bare bind.
    /// Lives here because the signer does — a write path that must name
    /// the testimony asks the binding rather than re-deriving the rule.
    pub fn testimony(&self) -> String {
        match &self.signer {
            Some(fp) => fp.to_hex(),
            None => "bare".to_string(),
        }
    }
}

/// What the HANDSHAKE established about one party: the three facts a
/// session's OPENING fixes (AUTH-3.16, AUTH-4.39) — everything
/// [`SessionBinding`] is but the `SessionId`, which M10 mints afterwards and
/// the route supplies.
///
/// Named rather than a triple because these ARE that type's fields: the route
/// reads them straight into one, and a reader of [`handshake`]'s signature
/// should not have to reach the call site to learn which absence is which.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Opened {
    pub principal: PrincipalId,
    pub signer: Option<Fingerprint>,
    pub scope: Scope,
}

/// A map lookup's three arms, constructed in ONE home so no call site can
/// mis-map them (AUTH-4.23).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    NoToken,
    Unknown,
    Found(SessionBinding),
}

/// The sessions store: token → binding, exclusion scoped to the map access
/// — `lookup` shared, `open`/`close` exclusive, no guard crossing `resolve`
/// (AUTH-4.24; RES-33). Process-lifetime, no cap, no TTL (AUTH-7.15's
/// declined knob — lazy eviction at presentation, `/session/close`, and
/// restart are the reclaim mechanisms, AUTH-1.53).
pub(crate) struct Sessions {
    /// Token → the binding it names — the contents, not the container:
    /// `close_binding` and `SessionBinding`'s own doc both say *binding*.
    bindings: parking_lot::RwLock<HashMap<Token, SessionBinding>>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions { bindings: parking_lot::RwLock::new(HashMap::new()) }
    }

    /// Mint a fresh token for `binding`: [`SESSION_TOKEN_BITS`] of CSPRNG
    /// output per call (AUTH-4.23).
    pub fn open(&self, binding: SessionBinding, rng: &mut impl CryptoRng) -> Token {
        let mut raw = [0u8; SESSION_TOKEN_BYTES];
        rng.fill_bytes(&mut raw);
        let token = Token(raw);
        self.bindings.write().insert(token.clone(), binding);
        token
    }

    /// `None` ⇒ `NoToken`, miss ⇒ `Unknown`, hit ⇒ `Found` (by value — no
    /// borrow outlives the lookup).
    pub fn lookup(&self, t: Option<&Token>) -> Lookup {
        match t {
            None => Lookup::NoToken,
            Some(t) => match self.bindings.read().get(t) {
                None => Lookup::Unknown,
                Some(b) => Lookup::Found(b.clone()),
            },
        }
    }

    /// Returns the closed binding — the `sid` the M10 close needs, with no
    /// second lookup.
    pub fn close(&self, t: &Token) -> Option<SessionBinding> {
        self.bindings.write().remove(t)
    }
}

/// The resolved actor of one request (AUTH-4.25). The glue
/// closes-and-signals on `Unknown | BindingDead` ONLY; `NoToken` has nothing
/// to close; a `RequestRefused` binding lives untouched.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Actor {
    Guest(GuestReason),
    Principal(SessionBinding),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestReason {
    NoToken,
    Unknown,
    BindingDead,
    RequestRefused,
}

// ── bare_bind_allowed & resolve (AUTH-4.26–4.31) ─────────────────────────

/// The bare-bind predicate's three-valued answer; the board's MODE is
/// tested FIRST (AUTH-4.27), so a cell where both the mode and the request
/// would refuse answers `ModeRefused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BareBind {
    Allowed,
    ModeRefused,
    RequestRefused,
}

/// AUTH-4.26 — the ONE home of the bare-bind rule: loopback peer, origin
/// header ok (absent ⇒ ok; present ⇒ parses AND in the BARE set; `null`
/// parses to nothing ⇒ refused), and the board's [`Mode`] not ENFORCING —
/// bare binds are honored in UNCLAIMED and CLAIMED-PERMISSIVE, never in
/// ENFORCING.
pub(crate) fn bare_bind_allowed(
    cfg: &AuthConfig,
    peer: Peer,
    origin_hdr: Option<&str>,
    claimed: bool,
) -> BareBind {
    if Mode::of(cfg, claimed) == Mode::Enforcing {
        return BareBind::ModeRefused;
    }
    if !peer.is_loopback() {
        return BareBind::RequestRefused;
    }
    let origin_ok = match origin_hdr {
        None => true,
        Some(h) => Origin::parse(h).is_some_and(|o| bare_origins(cfg).contains(&o)),
    };
    if origin_ok {
        BareBind::Allowed
    } else {
        BareBind::RequestRefused
    }
}

/// AUTH-4.30 (i) — WHOSE SET AUTHENTICATES, in THREE arms in this order:
/// `BOOTSTRAP_PRINCIPAL` ↦ the claimant (`None` while unclaimed, so an
/// unclaimed board's 0 signs with nothing, exactly as an unknown principal
/// — E6); then, where the principal's own account `a` holds an EMPTY
/// enrolled set, the NEAREST ACCOUNT ABOVE `a` WHOSE SET IS NOT — an
/// account that opens BY REFERENCE authenticates against its holder's set,
/// at every depth, until a genesis hands it away (RES-128); else `a`
/// itself; `None` for an unknown principal.
///
/// The walk is `parent()` arithmetic over account-tier ancestors and stops
/// at the account tier — no seam method, no M3 read beyond
/// `principal_prefix`. Where NO account above holds a set the answer is
/// `a`'s OWN address, whose set is empty (C-2): the two accessors stay
/// `Some` together, the walk always terminates, and step 5 refuses there.
///
/// OWNED, as the spec declares it: the walk's answer is an address this
/// function mints, which no borrow of the world can name. Resolved PER
/// REQUEST and never cached in the binding (AUTH-4.31) — which is what
/// makes E2's THIRD TRIGGER fall out of [`resolve`] with no code of its
/// own (RES-140): a genesis at the account a session acts as, or at any
/// account between it and the set it authenticated against, moves THIS
/// answer to a set the session's key is not in (the handoff latch,
/// AUTH-2.71, refuses a genesis naming a key of the set above).
pub(super) fn key_subject(world: &World, p: PrincipalId) -> Option<Address> {
    let identity = world.identity();
    if p == BOOTSTRAP_PRINCIPAL {
        return identity.claimant().cloned();
    }
    let own = world.m3().principal_prefix(p)?;
    Some(opening_account(identity, own))
}

/// AUTH-4.30 (i)'s walk from an ACCOUNT rather than a principal — the
/// account whose set OPENS `own`: `own` itself where its enrolled set is not
/// empty, else the nearest account above it whose set is not
/// ([`keyed_above`]), else `own` again, whose set is empty (C-2: the answer
/// is always an address, and the empty set refuses whatever reads it).
/// [`key_subject`] is this walk from a principal's own prefix; the record
/// grade's check takes it from a credential deposit's HOME account (signed
/// ops; the design record §4.5's table clause (a): "THE HOME'S OWN SET IS
/// NOT THE SET THAT OPENS IT" — a hire's genesis is homed in `X.1`'s doc 1,
/// and `X.1` holds no set of its own), so the daemon's session doors and its
/// record verify read one walk and cannot disagree about whose keys open an
/// account.
pub(super) fn opening_account(identity: &IdentityState, own: &Address) -> Address {
    if identity.key_set(own).is_empty() {
        if let Some(above) = keyed_above(identity, own) {
            return above;
        }
    }
    own.clone()
}

/// AUTH-4.30 (i)'s WALK, over an ADDRESS: the NEAREST ACCOUNT ABOVE `a`
/// whose enrolled set is not empty — `parent()` arithmetic over account-tier
/// ancestors, stopping at the account tier — or `None` where no account
/// above holds a set. `a`'s own set is not read: the walk starts above it.
///
/// ONE walk, two readers. [`key_subject`] takes it from a principal's own
/// account, which is what a session there authenticates against. The
/// precheck's slot (6) takes it from a previewed genesis's subject
/// (AUTH-3.21): the TERMINUS is the `S` the address test measures a genesis
/// at, "the account AUTH-4.30 (i)'s walk stops at" — so the two are this
/// one function, and a handoff is told at exactly the account whose keys
/// open the address it hands away (RES-172).
pub(super) fn keyed_above(identity: &IdentityState, a: &Address) -> Option<Address> {
    std::iter::successors(parent(a), parent)
        .take_while(|above| above.level() == Level::Account)
        .find(|above| !identity.key_set(above).is_empty())
}

/// AUTH-4.30 (ii) — THE SESSION'S OWN ACCOUNT, the one-arm map exactly:
/// `BOOTSTRAP_PRINCIPAL` ↦ the claimant, else the principal's own prefix;
/// `None` for an unknown principal. It disagrees with [`key_subject`] only
/// where an account opens by reference, and THE BLOCKED-PREFIX COMPARAND IS
/// THIS ONE's (step 4b; [`resolve`]'s blocked arm): an entry over exactly
/// `X.1` covers a session as `X.1`, whosever set opened it, and an entry
/// over `X.1` never reaches a session as `X`.
fn session_account(world: &World, p: PrincipalId) -> Option<Address> {
    if p == BOOTSTRAP_PRINCIPAL {
        world.identity().claimant().cloned()
    } else {
        world.m3().principal_prefix(p).cloned()
    }
}

/// AUTH-4.28 — the pure `Lookup` → `Actor` map at this snapshot. The
/// CALLER performs the one map lookup and passes the value; `resolve`
/// takes no store and holds no store guard. The key table it reads is
/// `world`'s own slice (`HasIdentity`, AUTH-2.60), so the state a binding is
/// judged by is one committed state by construction.
///
/// A `Found` binding meets THE BLOCK first (AUTH-4.63's second trigger):
/// where the installed list covers the session's OWN account — step 4b's
/// predicate, over [`session_account`] — the binding is DEAD, ARM-BLIND,
/// signed and bare alike, ahead of the bare arm's per-request conjunct for
/// the reason the mode is (AUTH-4.27): it holds for the holder everywhere
/// until a lift, so the cell where the request would also refuse answers
/// death and never `RequestRefused`. Config and NOT monotone (AUTH-4.45): a
/// lift is an install in which the entry is absent, and it resurrects
/// nothing — the next HANDSHAKE is what it admits.
pub(crate) fn resolve(
    cfg: &AuthConfig,
    lookup: Lookup,
    peer: Peer,
    origin_hdr: Option<&str>,
    world: &World,
) -> Actor {
    let identity = world.identity();
    let claimed = identity.claimant().is_some();
    match lookup {
        Lookup::NoToken => Actor::Guest(GuestReason::NoToken),
        Lookup::Unknown => Actor::Guest(GuestReason::Unknown),
        Lookup::Found(binding) => {
            let blocked = session_account(world, binding.principal)
                .is_some_and(|own| cfg.blocked_prefixes().covers(&own).is_some());
            if blocked {
                return Actor::Guest(GuestReason::BindingDead);
            }
            match binding.signer {
                Some(fp) => {
                    let live = key_subject(world, binding.principal)
                        .is_some_and(|a| identity.key_set(&a).contains(&fp));
                    if live {
                        Actor::Principal(binding)
                    } else {
                        Actor::Guest(GuestReason::BindingDead)
                    }
                }
                None => match bare_bind_allowed(cfg, peer, origin_hdr, claimed) {
                    BareBind::Allowed => Actor::Principal(binding),
                    BareBind::ModeRefused => Actor::Guest(GuestReason::BindingDead),
                    BareBind::RequestRefused => Actor::Guest(GuestReason::RequestRefused),
                },
            }
        }
    }
}

// ── the handshake (AUTH-4.32–4.41, AUTH-6.2–6.5) ─────────────────────────

/// The THREE exact `POST /session` body forms (AUTH-6.2): the bare body, the
/// signed body, and the SCOPED signed body — the last two one variant, told
/// apart by `scope`. A signed body WITHOUT the member is `Scope::Full`, the
/// second form byte for byte; one carrying `"scope": "content"` is
/// `Scope::Content`. The bare form has no scope to carry. The signed body's
/// `sig` is skep-identity's [`HybridBlob`], THE HYBRID BLOB (AUTH-4.34); the
/// body carries NO `alg` member and names no key.
pub(crate) enum SessionBody {
    Bare { principal: PrincipalId },
    Signed { principal: PrincipalId, nonce: Nonce, origin: Origin, scope: Scope, sig: HybridBlob },
}

/// The widths [`HybridBlob::parse_hex`] admits, as the handshake's 400 names
/// them — read off `SIG_ALGS` as the parse reads them, so the message and the
/// parse cannot disagree. Today:
/// `3373 bytes (tag 1, 6746 hex) or 730 bytes (tag 3, 1460 hex)`.
fn hybrid_sig_widths() -> String {
    SIG_ALGS
        .iter()
        .map(|row| format!("{} bytes (tag {}, {} hex)", row.sig_len(), row.tag, row.sig_len() * 2))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// The handshake refusal — a unit struct: the reason is DESTROYED at the
/// return, so nothing a route marshals can leak it (AUTH-4.35). The wire
/// answer is the ONE code, `401 session_rejected`, byte-identical across
/// causes.
///
/// `Debug` discloses nothing a unit struct could hold, and is what lets a
/// caller reach for the ordinary `Result` vocabulary — `expect_err` over a
/// hand-written `matches!` — on the handshake's answer.
#[derive(Debug)]
pub(crate) struct SessionRejected;

/// The handshake's TWO refusal values (AUTH-4.34). Every failure of the
/// CREDENTIAL is [`SessionRejected`], still a unit, so AUTH-4.35's
/// leak-unrepresentability stands as before. The SECOND value is step 4b's
/// and is distinct BY TYPE: it carries exactly one datum, public by
/// construction — the version address of the takedown record the longest
/// covering entry cites — and the route answers it `403 prefix_blocked`,
/// NEVER the 401 (AUTH-6.5): this party's credential was not read.
///
/// `Debug` carries nothing the wire withholds: the `Rejected` arm is the
/// unit, and `record` is the one datum AUTH-6.5 calls public by
/// construction — the address the 403 itself renders.
#[derive(Debug)]
pub(crate) enum HandshakeRefusal {
    Rejected(SessionRejected),
    Blocked { record: Address },
}

impl From<SessionRejected> for HandshakeRefusal {
    fn from(rejected: SessionRejected) -> HandshakeRefusal {
        HandshakeRefusal::Rejected(rejected)
    }
}

/// Parse the strict three-form body (AUTH-6.2, AUTH-6.3): the bare
/// `{"principal": n}`, the signed four-field form, or the SCOPED signed form
/// carrying `"scope": "content"` beside them — all three signed fields, and
/// `scope` when present a FOURTH, validated BEFORE anything burns. Any
/// failure is the 400 `malformed_session_request` and the nonce survives: a
/// scope fault is a syntax fault as the other three are, and so is a `sig`
/// whose width is none of the hybrid blob widths ([`HybridBlob::parse_hex`])
/// — a blob no other width can be built as, so the wrong-width-as-401 reading
/// cannot be written. The record grade reads a credential record's `sig`
/// through the same parse (`policy/credential.rs`'s step 3), so the two doors
/// admit one width set, each answering a refusal in its own vocabulary — this
/// door's 400 whose nonce survives, the record grade's
/// `attestation_invalid:malformed`. `Err(detail)` is the 400's detail text.
///
/// `scope` is the signed form's alone. On the BARE body it is "any other
/// body" (AUTH-6.2), whatever its value — the bare arm is scope-less — so a
/// client asking for the limit is never opened as something it did not ask
/// for.
pub(crate) fn parse_session_body(body: &[u8]) -> Result<SessionBody, String> {
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(m) = v else {
        return Err("session request must be a JSON object".into());
    };
    let principal = m
        .get("principal")
        .and_then(Value::as_u64)
        .ok_or("missing or non-integer field 'principal'")?;
    let principal = PrincipalId(principal);
    // The codec's never-silent device, so a client's typo is a named
    // failure here exactly as in a frame — and its echo of the offending
    // key is bounded, which a hand-rolled one is not.
    check_keys(&m, &["principal", "nonce", "origin", "scope", "sig"])?;
    let signed_fields =
        [m.get("nonce"), m.get("origin"), m.get("sig")].iter().filter(|f| f.is_some()).count();
    match signed_fields {
        0 if m.contains_key("scope") => {
            Err("field 'scope' belongs to the signed session body alone".into())
        }
        0 => Ok(SessionBody::Bare { principal }),
        3 => {
            let origin_text = m
                .get("origin")
                .and_then(Value::as_str)
                .ok_or("field 'origin' must be a string")?;
            // Already canonical, or 400 (AUTH-4.36 item 1).
            let origin = Origin::parse(origin_text)
                .ok_or("field 'origin' is not a canonical origin")?;
            let nonce_text =
                m.get("nonce").and_then(Value::as_str).ok_or("field 'nonce' must be a string")?;
            let nonce = Nonce::parse_hex(nonce_text)
                .ok_or("field 'nonce' is not 64 lowercase hex")?;
            let sig_text =
                m.get("sig").and_then(Value::as_str).ok_or("field 'sig' must be a string")?;
            let sig = HybridBlob::parse_hex(sig_text).ok_or_else(|| {
                format!(
                    "field 'sig' is not hex decoding to a hybrid signature blob of exactly {}",
                    hybrid_sig_widths()
                )
            })?;
            // The FOURTH strict field (AUTH-6.3): absent is FULL; present, it
            // is exactly the JSON string `content` — no other value, no
            // other type, no case variant.
            let scope = match m.get("scope") {
                None => Scope::Full,
                Some(Value::String(s)) if s == Scope::CONTENT => Scope::Content,
                Some(_) => return Err("field 'scope' must be exactly \"content\"".into()),
            };
            Ok(SessionBody::Signed { principal, nonce, origin, scope, sig })
        }
        _ => Err("a signed session body carries nonce, origin and sig together".into()),
    }
}

/// AUTH-6.4 — the signed bytes, VERSIONED and never extended in place. An
/// UNSCOPED body signs the v1 layout, `framed(SESSION_TAG, [origin, nonce,
/// principal-as-shortest-decimal])`; a SCOPED body signs the v2 layout,
/// `framed(SESSION_TAG_V2, [origin, nonce, principal, scope])` — each over
/// the body's OWN strings; the daemon canonicalizes NOTHING on this path.
///
/// ONE payload per body, chosen by the body's own scope, so a scoped body is
/// verified under v2 ONLY and an unscoped body under v1 ONLY: the framing tag
/// (`SESSION_TAG` or `SESSION_TAG_V2`, AUTH-1.11) names the grammar, a v1
/// signature never opens a scoped session and a v2 signature never opens an
/// unscoped one. The scope is therefore the SIGNER's declaration — a limit
/// the signer did not sign could be lifted on the path by dropping the
/// field. BOTH NAMES CARRY THE HYBRID LAYOUT (the naming ruling, owner
/// 2026-09-26 "keep v1/v2 names"): the key's two halves sign these SAME
/// bytes and `sig` holds the post-quantum signature then the Ed25519
/// signature — the field list unchanged, no `skep-session-v3`/`-v4`.
fn session_payload(
    origin: &Origin,
    nonce_hex: &str,
    p: PrincipalId,
    scope: Scope,
) -> Vec<u8> {
    let principal = p.0.to_string();
    let [origin, nonce, principal] =
        [origin.as_str().as_bytes(), nonce_hex.as_bytes(), principal.as_bytes()];
    match scope {
        Scope::Full => framed(SESSION_TAG, &[origin, nonce, principal]),
        Scope::Content => {
            framed(SESSION_TAG_V2, &[origin, nonce, principal, Scope::CONTENT.as_bytes()])
        }
    }
}

/// AUTH-4.32 — the HYBRID verification under the KEY's own `ALGS` row:
/// [`skep_signature::verify`] under the key's marker tag — the post-quantum
/// half of the blob under the key's post-quantum half, the Ed25519 half under
/// its Ed25519 half by strict verification (`verify_strict`), BOTH over the
/// SAME payload; either failing fails, and NO HALF OPENS A SESSION ALONE.
/// `false` on a blob that is not the row's width (a tag-3 blob against a
/// tag-1 key is `Malformed` there, never a panic) and on an undecodable key
/// or signature; never panics. Both halves' decodes inside it are the two the
/// precheck's `undecodable_key` courtesy runs
/// ([`skep_signature::key_decodes`]) — one pair of functions in
/// `skep-signature`, which is what keeps the two answering alike.
fn verify(key: &PublicKey, payload: &[u8], sig: &[u8]) -> bool {
    skep_signature::verify(key.sig_alg_row().tag, key, payload, sig).is_ok()
}

/// AUTH-4.33 — try EVERY enrolled key in fingerprint order, EACH UNDER ITS
/// OWN ROW — the body names no key and no algorithm, the blob's width being
/// the syntax check alone — no cutoff, ever — returning the fingerprint
/// alone.
fn find_signer(set: &KeySet, payload: &[u8], sig: &[u8]) -> Option<Fingerprint> {
    set.enrolled().find(|(_, e)| verify(&e.key, payload, sig)).map(|(fp, _)| *fp)
}

/// The handshake (AUTH-4.36/4.37): the signed arm's pinned order — origin
/// set, burn, the account, THE BLOCK (step 4b), key subject, key set,
/// payload, find_signer — and the bare arm's one predicate. Every failure
/// of the credential is the same unit refusal; step 4b's is the second
/// value, [`HandshakeRefusal::Blocked`].
///
/// The BARE arm is untouched by the list (AUTH-4.37; RES-65 item 3's named
/// residue): a bare bind naming a principal under a listed prefix is
/// admitted as written — reachable only in CLAIMED-PERMISSIVE on loopback,
/// which no deployment that issues a list runs — and [`resolve`]'s blocked
/// arm, which is arm-blind, kills it at its first presentation.
///
/// THE SCOPE is part of the answer (AUTH-4.39): a signed body's own, handed
/// back only once its signature verified under the layout that scope names —
/// so the binding the route opens carries a scope its signer SIGNED, and
/// never one read off an unverified request. The bare arm answers
/// `Scope::Full`: it is scope-less, `Full` in shape.
///
/// The key table every step reads is `world`'s own slice (`HasIdentity`,
/// AUTH-2.60): the account registry and the set a signature is tried
/// against are one committed state by construction.
pub(crate) fn handshake(
    cfg: &AuthConfig,
    challenges: &Challenges,
    world: &World,
    body: SessionBody,
    peer: Peer,
    origin_hdr: Option<&str>,
    now: Instant,
) -> Result<Opened, HandshakeRefusal> {
    let identity = world.identity();
    let claimed = identity.claimant().is_some();
    match body {
        SessionBody::Bare { principal } => {
            match bare_bind_allowed(cfg, peer, origin_hdr, claimed) {
                BareBind::Allowed => {
                    Ok(Opened { principal, signer: None, scope: Scope::Full })
                }
                _ => Err(SessionRejected.into()),
            }
        }
        SessionBody::Signed { principal, nonce, origin, scope, sig } => {
            // 2 — the signed set (the bare set until the claim's drop).
            if !signed_origins(cfg, claimed).contains(&origin) {
                return Err(SessionRejected.into());
            }
            // 3 — the burn: unknown, expired, wrong-principal, reused all
            // die here, and the entry is gone either way.
            if !challenges.burn(&nonce, principal, now) {
                return Err(SessionRejected.into());
            }
            // 4 — the account, which takes TWO values (AUTH-4.30): the
            // session's OWN for step 4b, whose set authenticates for step
            // 5. They are `Some` together (C-2), so the unknown-principal
            // arm — principal 0 on an unclaimed board included — is this
            // one refusal, and a party naming a principal the board does
            // not know is never told a prefix is blocked.
            let Some(own) = session_account(world, principal) else {
                return Err(SessionRejected.into());
            };
            // 4b — THE BLOCK: the account KNOWN, no key set read and no
            // signature verified for a party the board refuses. The nonce
            // is SPENT (step 3 stands ahead) and no re-challenge is owed:
            // the refusal is permanent until a lift. A config-fed gate in
            // step 2's own shape — the daemon reads no record.
            if let Some(record) = cfg.blocked_prefixes().covers(&own) {
                return Err(HandshakeRefusal::Blocked { record: record.clone() });
            }
            // 5 — the subject's set. The subject is read HERE, behind 4b,
            // because its walk reads key sets; ahead of 4b it would answer
            // nothing 4b needs.
            let Some(subject) = key_subject(world, principal) else {
                return Err(SessionRejected.into());
            };
            let set = identity.key_set(&subject);
            if set.is_empty() {
                return Err(SessionRejected.into());
            }
            // 6/7 — the signature over the body's OWN strings, under the
            // layout the body's scope names: v2 for a scoped body, v1 for an
            // unscoped one, and never the other (AUTH-6.4) — the HYBRID BLOB,
            // both halves, every enrolled key tried under its own row. A v1
            // signature over a scoped body, a blob one half of which fails,
            // or a well-formed blob no enrolled key verifies fails here — the
            // one 401, like any signature failure.
            let payload = session_payload(&origin, &nonce.to_hex(), principal, scope);
            match find_signer(set, &payload, sig.as_bytes()) {
                Some(fp) => Ok(Opened { principal, signer: Some(fp), scope }),
                None => Err(SessionRejected.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests;
