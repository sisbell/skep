//! The session layer (AUTH part 04): nonces and the challenge store, the
//! session token and store, per-request resolution, and the handshake.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use ed25519_dalek::Signature;
use rand_core::CryptoRng;
use serde_json::Value;
use skep_febe::SessionId;
use skep_identity::{framed, Fingerprint, IdentityState, KeySet, SESSION_TAG, SESSION_TAG_V2};
use skep_namespace::{PrincipalId, BOOTSTRAP_PRINCIPAL};

use super::{bare_origins, blocked_prefixes, signed_origins, AuthConfig, Mode, Origin};
use crate::codec::{check_keys, hex_nibble, hex_string};
use crate::World;
use skep_address::{parent, Address, Level};
use skep_namespace::HasM3;

/// The challenge TTL — a PIN, not a knob: `ttl_ms` on the wire is a byte
/// pin of this constant (AUTH-4.12).
pub(crate) const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// Session-token unpredictability (AUTH-4.13): at least this many bits per
/// token from a `CryptoRng` — never a per-process prefix plus a counter.
pub(crate) const SESSION_TOKEN_BITS: usize = 128;

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
    pub(crate) fn is_loopback(self) -> bool {
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

/// Exactly `N` bytes of LOWERCASE hex, or `None` — the admission rule both
/// wire tokens rest on. Each `parse` admits only what its own emitter
/// produces, so an uppercase value is refused rather than normalized; what
/// that costs a caller is per-type and stays stated on each. The REFUSAL is
/// this function's own, in the byte it hands [`hex_nibble`]: that table is
/// lowercase and is the crate's one hex mapping, so case is the only thing
/// this and the content forms' decode differ by.
fn parse_lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut raw = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        raw[i] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(raw)
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
    /// structures whether or not it validates; true iff present, unexpired,
    /// and issued for `principal`.
    pub fn burn(&self, nonce: &Nonce, principal: PrincipalId, now: Instant) -> bool {
        let mut inner = self.inner.lock();
        let entry = inner.map.remove(nonce);
        inner.order.retain(|n| n != nonce);
        matches!(entry, Some((p, expires)) if p == principal && now < expires)
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
    /// The key testimony of a write this session commits (AUTH-4.48): the
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
pub(crate) fn key_subject(
    world: &World,
    identity: &IdentityState,
    p: PrincipalId,
) -> Option<Address> {
    if p == BOOTSTRAP_PRINCIPAL {
        return identity.claimant().cloned();
    }
    let own = world.m3().principal_prefix(p)?;
    if identity.key_set(own).is_empty() {
        if let Some(above) = keyed_above(identity, own) {
            return Some(above);
        }
    }
    Some(own.clone())
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
pub(crate) fn keyed_above(identity: &IdentityState, a: &Address) -> Option<Address> {
    let mut cursor = parent(a);
    while let Some(above) = cursor.filter(|a| a.level() == Level::Account) {
        if !identity.key_set(&above).is_empty() {
            return Some(above);
        }
        cursor = parent(&above);
    }
    None
}

/// AUTH-4.30 (ii) — THE SESSION'S OWN ACCOUNT, the one-arm map exactly:
/// `BOOTSTRAP_PRINCIPAL` ↦ the claimant, else the principal's own prefix;
/// `None` for an unknown principal. It disagrees with [`key_subject`] only
/// where an account opens by reference, and THE BLOCKED-PREFIX COMPARAND IS
/// THIS ONE's (step 4b; [`resolve`]'s blocked arm): an entry over exactly
/// `X.1` covers a session as `X.1`, whosever set opened it, and an entry
/// over `X.1` never reaches a session as `X`.
pub(crate) fn session_account(
    world: &World,
    identity: &IdentityState,
    p: PrincipalId,
) -> Option<Address> {
    if p == BOOTSTRAP_PRINCIPAL {
        identity.claimant().cloned()
    } else {
        world.m3().principal_prefix(p).cloned()
    }
}

/// AUTH-4.28 — the pure `Lookup` → `Actor` map at this snapshot. The
/// CALLER performs the one map lookup and passes the value; `resolve`
/// takes no store and holds no store guard. The identity state rides
/// beside the world (the fold-beside-engine build; the spec reads it off
/// `world.identity()`).
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
    identity: &IdentityState,
) -> Actor {
    let claimed = identity.claimant().is_some();
    match lookup {
        Lookup::NoToken => Actor::Guest(GuestReason::NoToken),
        Lookup::Unknown => Actor::Guest(GuestReason::Unknown),
        Lookup::Found(binding) => {
            let blocked = session_account(world, identity, binding.principal)
                .is_some_and(|own| blocked_prefixes(cfg).covers(&own).is_some());
            if blocked {
                return Actor::Guest(GuestReason::BindingDead);
            }
            match binding.signer {
                Some(fp) => {
                    let live = key_subject(world, identity, binding.principal)
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
/// `Scope::Content`. The bare form has no scope to carry.
pub(crate) enum SessionBody {
    Bare { principal: PrincipalId },
    Signed { principal: PrincipalId, nonce: Nonce, origin: Origin, scope: Scope, sig: [u8; 64] },
}

/// The handshake refusal — a unit struct: the reason is DESTROYED at the
/// return, so nothing a route marshals can leak it (AUTH-4.35). The wire
/// answer is the ONE code, `401 session_rejected`, byte-identical across
/// causes.
pub(crate) struct SessionRejected;

/// The handshake's TWO refusal values (AUTH-4.34). Every failure of the
/// CREDENTIAL is [`SessionRejected`], still a unit, so AUTH-4.35's
/// leak-unrepresentability stands as before. The SECOND value is step 4b's
/// and is distinct BY TYPE: it carries exactly one datum, public by
/// construction — the version address of the takedown record the longest
/// covering entry cites — and the route answers it `403 prefix_blocked`,
/// NEVER the 401 (AUTH-6.5): this party's credential was not read.
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
/// scope fault is a syntax fault as the other three are. `Err(detail)` is
/// the 400's detail text.
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
            let sig = parse_sig(sig_text)
                .ok_or("field 'sig' is not 128 hex characters decoding to 64 bytes")?;
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

/// `sig`: 128 hex decoding to exactly 64 bytes — case-free (decoded, never
/// framed).
fn parse_sig(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut raw = [0u8; 64];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0].to_ascii_lowercase())?;
        let lo = hex_nibble(chunk[1].to_ascii_lowercase())?;
        raw[i] = (hi << 4) | lo;
    }
    Some(raw)
}

/// AUTH-6.4 — the signed bytes, VERSIONED and never extended in place. An
/// UNSCOPED body signs the v1 layout, `framed(SESSION_TAG, [origin, nonce,
/// principal-as-shortest-decimal])`; a SCOPED body signs the v2 layout,
/// `framed(SESSION_TAG_V2, [origin, nonce, principal, scope])` — each over
/// the body's OWN strings; the daemon canonicalizes NOTHING on this path.
///
/// ONE payload per body, chosen by the body's own scope, so a scoped body is
/// verified under v2 ONLY and an unscoped body under v1 ONLY: the tag names
/// the grammar, a v1 signature never opens a scoped session and a v2
/// signature never opens an unscoped one. The scope is therefore the
/// SIGNER's declaration — a limit the signer did not sign could be lifted on
/// the path by dropping the field.
pub(crate) fn session_payload(
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

/// AUTH-4.32 — Ed25519 strict verification (`verify_strict` semantics);
/// false on an undecodable key or signature; never panics. The decode is
/// [`super::verifying_key`]'s, which is what keeps this and the precheck's
/// `undecodable_key` slot answering alike.
fn verify(key: &skep_identity::PublicKey, payload: &[u8], sig: &[u8; 64]) -> bool {
    super::verifying_key(key)
        .is_some_and(|vk| vk.verify_strict(payload, &Signature::from_bytes(sig)).is_ok())
}

/// AUTH-4.33 — try EVERY enrolled key in fingerprint order — no cutoff,
/// ever — returning the fingerprint alone.
fn find_signer(set: &KeySet, payload: &[u8], sig: &[u8; 64]) -> Option<Fingerprint> {
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn handshake(
    cfg: &AuthConfig,
    challenges: &Challenges,
    world: &World,
    identity: &IdentityState,
    body: SessionBody,
    peer: Peer,
    origin_hdr: Option<&str>,
    now: Instant,
) -> Result<(PrincipalId, Option<Fingerprint>, Scope), HandshakeRefusal> {
    let claimed = identity.claimant().is_some();
    match body {
        SessionBody::Bare { principal } => {
            match bare_bind_allowed(cfg, peer, origin_hdr, claimed) {
                BareBind::Allowed => Ok((principal, None, Scope::Full)),
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
            let Some(own) = session_account(world, identity, principal) else {
                return Err(SessionRejected.into());
            };
            // 4b — THE BLOCK: the account KNOWN, no key set read and no
            // signature verified for a party the board refuses. The nonce
            // is SPENT (step 3 stands ahead) and no re-challenge is owed:
            // the refusal is permanent until a lift. A config-fed gate in
            // step 2's own shape — the daemon reads no record.
            if let Some(record) = blocked_prefixes(cfg).covers(&own) {
                return Err(HandshakeRefusal::Blocked { record: record.clone() });
            }
            // 5 — the subject's set. The subject is read HERE, behind 4b,
            // because its walk reads key sets; ahead of 4b it would answer
            // nothing 4b needs.
            let Some(subject) = key_subject(world, identity, principal) else {
                return Err(SessionRejected.into());
            };
            let set = identity.key_set(&subject);
            if set.is_empty() {
                return Err(SessionRejected.into());
            }
            // 6/7 — the signature over the body's OWN strings, under the
            // layout the body's scope names: v2 for a scoped body, v1 for an
            // unscoped one, and never the other (AUTH-6.4). A v1 signature
            // over a scoped body fails here — the one 401, like any
            // signature failure.
            let payload = session_payload(&origin, &nonce.to_hex(), principal, scope);
            match find_signer(set, &payload, &sig) {
                Some(fp) => Ok((principal, Some(fp), scope)),
                None => Err(SessionRejected.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use skep_engine::Engine;
    use skep_febe::OperationSurface;
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig};

    use super::super::AuthOptions;
    use super::*;

    /// A config bound at `port`, with no configured origin — so the bare
    /// set is exactly the three loopback defaults and every membership
    /// answer below is the defaults' own.
    fn cfg_at(port: u16, local_trust: bool) -> AuthConfig {
        let cfg = AuthConfig::new(AuthOptions { local_trust, ..AuthOptions::default() });
        cfg.bind_port(port).expect("a fresh config binds once");
        cfg
    }

    /// AUTH-4.16 — strict lowercase nonces: the round trip is
    /// byte-identical, uppercase refuses.
    #[test]
    fn nonce_hex_is_strict_lowercase() {
        let n = Nonce([0xab; 32]);
        assert_eq!(n.to_hex(), "ab".repeat(32));
        assert_eq!(Nonce::parse_hex(&n.to_hex()), Some(n));
        assert!(Nonce::parse_hex(&"AB".repeat(32)).is_none(), "uppercase is a syntax fault");
        assert!(Nonce::parse_hex("ab").is_none());
    }

    /// AUTH-4.17 — token round-trip and strict admission.
    #[test]
    fn token_parse_admits_only_to_wire_output() {
        let t = Token([0xab; 16]);
        // Compared through `to_wire`, which is injective (AUTH-4.17), so
        // this is the same property — and a failure names the wire form
        // rather than the two `<redacted>`s `Token`'s own `Debug` prints.
        assert_eq!(Token::parse(&t.to_wire()).map(|p| p.to_wire()), Some(t.to_wire()));
        assert!(Token::parse("nonsense").is_none());
        assert!(Token::parse(&t.to_wire().to_uppercase()).is_none());
        // The old daemon's prefix.suffix shape is refused — AUTH-7.25 names
        // it as exactly the forbidden one.
        assert!(Token::parse("9f3a6c21d4b8e07a.1").is_none());
    }

    /// AUTH-4.21 — single use: a burned nonce is gone whether or not it
    /// validated; expiry and wrong-principal both burn.
    #[test]
    fn challenges_are_single_use_and_expire() {
        let ch = Challenges::new(4);
        let mut rng = super::super::OsEntropy;
        let now = Instant::now();
        let n = ch.issue(PrincipalId(7), now, &mut rng);
        assert!(!ch.burn(&n, PrincipalId(8), now), "wrong principal refuses");
        assert!(!ch.burn(&n, PrincipalId(7), now), "and the entry burned with it");
        let n2 = ch.issue(PrincipalId(7), now, &mut rng);
        assert!(!ch.burn(&n2, PrincipalId(7), now + CHALLENGE_TTL), "expiry refuses");
        let n3 = ch.issue(PrincipalId(7), now, &mut rng);
        assert!(ch.burn(&n3, PrincipalId(7), now + Duration::from_secs(1)));
        assert!(!ch.burn(&n3, PrincipalId(7), now + Duration::from_secs(1)), "single use");
    }

    /// AUTH-4.26 — the bare-bind cells, the board's MODE first: a loopback
    /// peer at an admitted origin is refused in ENFORCING, and a
    /// non-loopback peer or an unadmitted origin is refused for THIS
    /// REQUEST, which is not death.
    #[test]
    fn bare_bind_cells_answer_mode_before_request() {
        let cfg = cfg_at(8642, true);
        let dialed = format!("http://127.0.0.1:{}", 8642);
        // UNCLAIMED and CLAIMED-PERMISSIVE both honor the bare bind.
        for claimed in [false, true] {
            assert_eq!(
                bare_bind_allowed(&cfg, Peer::Loopback, None, claimed),
                BareBind::Allowed,
                "claimed={claimed}: an absent Origin is ok"
            );
            assert_eq!(
                bare_bind_allowed(&cfg, Peer::Loopback, Some(&dialed), claimed),
                BareBind::Allowed,
                "claimed={claimed}: a loopback default is in the bare set"
            );
            assert_eq!(
                bare_bind_allowed(&cfg, Peer::Remote, None, claimed),
                BareBind::RequestRefused,
                "claimed={claimed}: a non-loopback peer is refused for this request"
            );
            for bad in ["https://evil.example", "null", "http://127.0.0.1:9999"] {
                assert_eq!(
                    bare_bind_allowed(&cfg, Peer::Loopback, Some(bad), claimed),
                    BareBind::RequestRefused,
                    "claimed={claimed}: '{bad}' is not in the bare set"
                );
            }
        }
        // The claimed board with the flag off is ENFORCING, which answers
        // the MODE refusal FIRST — so a cell where both the mode and the
        // request would refuse still answers `ModeRefused`. The same config
        // reads UNCLAIMED before the claim, which is the last cell.
        let enforcing_cfg = cfg_at(8642, false);
        assert_eq!(Mode::of(&enforcing_cfg, true), Mode::Enforcing);
        assert_eq!(Mode::of(&enforcing_cfg, false), Mode::Unclaimed, "the flag is not consulted");
        assert_eq!(Mode::of(&cfg, true), Mode::ClaimedPermissive, "claimed with the flag on");
        assert_eq!(
            bare_bind_allowed(&enforcing_cfg, Peer::Loopback, Some(&dialed), true),
            BareBind::ModeRefused,
            "the mode is tested first"
        );
        assert_eq!(
            bare_bind_allowed(&enforcing_cfg, Peer::Remote, Some("null"), true),
            BareBind::ModeRefused
        );
        assert_eq!(
            bare_bind_allowed(&enforcing_cfg, Peer::Loopback, None, false),
            BareBind::Allowed,
            "pre-claim the flag is not consulted"
        );
    }

    /// AUTH-4.25/4.28 — the `Lookup` → `Actor` map, arm by arm. `resolve`
    /// decides whether a request may write at all, and every arm but
    /// `Principal` answers with a REASON the glue dispatches on: only
    /// `Unknown` and `BindingDead` close the binding.
    #[test]
    fn resolve_maps_every_lookup_arm_to_its_actor() {
        let engine = Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        })
        .expect("in-memory genesis cannot fail");
        let febe = OperationSurface::new(Box::new(engine.stores()));
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        // Genesis: no account holds any key, so no signed binding is live.
        let identity = IdentityState::genesis();
        let cfg = cfg_at(8642, true);
        let go = |lookup, peer, origin| resolve(&cfg, lookup, peer, origin, world, &identity);

        assert_eq!(
            go(Lookup::NoToken, Peer::Loopback, None),
            Actor::Guest(GuestReason::NoToken),
            "no token: nothing to close"
        );
        assert_eq!(
            go(Lookup::Unknown, Peer::Loopback, None),
            Actor::Guest(GuestReason::Unknown),
            "an unknown token: the glue closes and signals"
        );

        let bare = SessionBinding {
            sid: febe.open_session(PrincipalId(7)),
            principal: PrincipalId(7),
            signer: None,
            scope: Scope::Full,
        };
        assert_eq!(
            go(Lookup::Found(bare.clone()), Peer::Loopback, None),
            Actor::Principal(bare.clone()),
            "a bare bind the mode honors resolves to its principal"
        );
        assert_eq!(
            go(Lookup::Found(bare.clone()), Peer::Remote, None),
            Actor::Guest(GuestReason::RequestRefused),
            "a bare bind off loopback: refused for this request, and it LIVES"
        );

        // A signed binding whose key no account holds is DEAD — the arm the
        // glue closes on, and the one a retirement produces.
        let signed = SessionBinding {
            signer: Fingerprint::parse_hex(&"ab".repeat(32)),
            ..bare
        };
        assert!(signed.signer.is_some(), "the fixture fingerprint parses");
        // The signed arm consults no origin and no peer — dead is dead —
        // which is why the two cells below must answer alike.
        for peer in [Peer::Loopback, Peer::Remote] {
            assert_eq!(
                go(Lookup::Found(signed.clone()), peer, Some("https://evil.example")),
                Actor::Guest(GuestReason::BindingDead),
                "{peer:?}: a signer no key set holds is dead"
            );
        }
    }

    /// AUTH-4.62 item 1's EXPIRED arm — the one of the thirteen no wire test
    /// drives, since reaching it over HTTP needs the 60 s TTL. Here `now` is
    /// an argument: a nonce presented at its expiry dies at the burn and is
    /// the UNIT refusal, which `session_refused` marshals to the one 401
    /// body — byte-identical with every other arm by construction — and
    /// never the second value, which only step 4b produces.
    #[test]
    fn an_expired_nonce_is_the_unit_refusal() {
        let engine = Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        })
        .expect("in-memory genesis cannot fail");
        let snap = engine.kernel().snapshot();
        let identity = IdentityState::genesis();
        let cfg = cfg_at(8642, true);
        let challenges = Challenges::new(4);
        let issued = Instant::now();
        let principal = PrincipalId(7);
        let nonce = challenges.issue(principal, issued, &mut super::super::OsEntropy);
        let body = SessionBody::Signed {
            principal,
            nonce,
            // UNCLAIMED, so the signed set is the bare set and the dialed
            // loopback default passes step 2: what refuses is the burn.
            origin: Origin::parse("http://127.0.0.1:8642").expect("canonical"),
            scope: Scope::Full,
            sig: [0u8; 64],
        };
        let outcome = handshake(
            &cfg,
            &challenges,
            snap.world(),
            &identity,
            body,
            Peer::Loopback,
            None,
            issued + CHALLENGE_TTL,
        );
        assert!(
            matches!(outcome, Err(HandshakeRefusal::Rejected(SessionRejected))),
            "an expired nonce is a failure of the credential: the unit refusal"
        );
        assert!(
            !challenges.burn(&nonce, principal, issued),
            "and the expired entry burned with the attempt"
        );
    }

    /// AUTH-6.2/6.3 — the THREE body forms and the strict fourth field. A
    /// signed body without `scope` is FULL (the second form, byte for byte);
    /// `scope` takes exactly the JSON string `content`; any other value or
    /// type — and `scope` on the BARE body, whatever it holds — is "any other
    /// body". The parse stands ahead of the burn, so each `Err` here is a 400
    /// that spends no nonce.
    #[test]
    fn the_session_body_takes_three_forms_and_scope_is_strict() {
        let signed = |scope: &str| {
            format!(
                r#"{{"principal":7,"nonce":"{}","origin":"http://127.0.0.1:8642"{scope},"sig":"{}"}}"#,
                "ab".repeat(32),
                "cd".repeat(64)
            )
        };
        assert!(matches!(
            parse_session_body(br#"{"principal":7}"#),
            Ok(SessionBody::Bare { principal: PrincipalId(7) })
        ));
        assert!(matches!(
            parse_session_body(signed("").as_bytes()),
            Ok(SessionBody::Signed { scope: Scope::Full, .. })
        ));
        assert!(matches!(
            parse_session_body(signed(r#","scope":"content""#).as_bytes()),
            Ok(SessionBody::Signed { scope: Scope::Content, .. })
        ));
        // No `full` spelling, no case variant, no other type: absence IS full.
        for bad in [
            r#""full""#,
            r#""Content""#,
            r#""CONTENT""#,
            r#""content ""#,
            r#""""#,
            "null",
            "true",
            "1",
            r#"["content"]"#,
            r#"{"content":true}"#,
        ] {
            assert!(
                parse_session_body(signed(&format!(r#","scope":{bad}"#)).as_bytes()).is_err(),
                "scope {bad} is a syntax fault"
            );
        }
        // The bare arm is scope-less: even the one admitted value refuses.
        for bare in [r#"{"principal":7,"scope":"content"}"#, r#"{"principal":7,"scope":null}"#] {
            assert!(parse_session_body(bare.as_bytes()).is_err(), "{bare}");
        }
        // …and a scope does not complete a partial signed triple.
        assert!(parse_session_body(
            format!(r#"{{"principal":7,"nonce":"{}","scope":"content"}}"#, "ab".repeat(32))
                .as_bytes()
        )
        .is_err());
    }

    /// AUTH-6.4 — the layout is VERSIONED: an unscoped body signs the v1
    /// bytes, unmoved, and a scoped body the v2 bytes — the same three fields
    /// then `be32(|scope|)‖scope`, the body's own `content`. Pinned as BYTES,
    /// spelled by hand: this is the reference layout a client signs.
    #[test]
    fn a_scoped_body_signs_the_v2_layout_and_an_unscoped_one_the_v1() {
        let origin = Origin::parse("http://127.0.0.1:8642").expect("canonical");
        let nonce = "ab".repeat(32);
        let field = |bytes: &[u8]| {
            let len = u32::try_from(bytes.len()).expect("a field fits be32");
            [&len.to_be_bytes()[..], bytes].concat()
        };
        let body = [
            field(origin.as_str().as_bytes()),
            field(nonce.as_bytes()),
            field(b"42"), // the principal as shortest ASCII decimal
        ]
        .concat();

        let v1 = [&b"skep-session-v1"[..], &body].concat();
        assert_eq!(session_payload(&origin, &nonce, PrincipalId(42), Scope::Full), v1);
        let v2 = [&b"skep-session-v2"[..], &body, &field(b"content")].concat();
        assert_eq!(session_payload(&origin, &nonce, PrincipalId(42), Scope::Content), v2);
        // Neither is a prefix of the other, so no signature over one layout
        // verifies over the other.
        assert!(!v2.starts_with(&v1) && !v1.starts_with(&v2));
    }

    /// AUTH-4.20 — the cap evicts oldest-first.
    #[test]
    fn challenge_cap_evicts_oldest() {
        let ch = Challenges::new(2);
        let mut rng = super::super::OsEntropy;
        let now = Instant::now();
        let a = ch.issue(PrincipalId(1), now, &mut rng);
        let b = ch.issue(PrincipalId(1), now, &mut rng);
        let c = ch.issue(PrincipalId(1), now, &mut rng);
        assert!(!ch.burn(&a, PrincipalId(1), now), "the oldest was evicted");
        assert!(ch.burn(&b, PrincipalId(1), now));
        assert!(ch.burn(&c, PrincipalId(1), now));
    }
}
