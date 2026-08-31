//! The session layer (AUTH part 04): nonces and the challenge store, the
//! session token and store, per-request resolution, and the handshake.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::CryptoRng;
use serde_json::Value;
use skep_febe::SessionId;
use skep_identity::{framed, Fingerprint, IdentityState, KeySet, SESSION_TAG};
use skep_namespace::{PrincipalId, BOOTSTRAP_PRINCIPAL};

use super::{bare_origins, signed_origins, AuthConfig, Origin};
use crate::World;
use skep_address::Address;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        hex_lower(&self.0)
    }

    /// ONLY 64 lowercase hex — deliberately narrower than
    /// `Fingerprint::parse_hex` (AUTH-4.16): an uppercase nonce is a 400
    /// syntax fault whose nonce SURVIVES, never a burned 401.
    pub fn parse_hex(s: &str) -> Option<Nonce> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        let mut raw = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            raw[i] = (hi << 4) | lo;
        }
        Some(Nonce(raw))
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
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
        let mut g = self.inner.lock();
        g.map.insert(nonce, (principal, now + CHALLENGE_TTL));
        g.order.push_back(nonce);
        while g.order.len() > self.cap {
            if let Some(old) = g.order.pop_front() {
                g.map.remove(&old);
            }
        }
        nonce
    }

    /// SINGLE-USE: removes the entry from BOTH structures whether or not it
    /// validates (AUTH-4.21); true iff present, unexpired, and issued for
    /// `principal`.
    pub fn take(&self, nonce: &Nonce, principal: PrincipalId, now: Instant) -> bool {
        let mut g = self.inner.lock();
        let entry = g.map.remove(nonce);
        g.order.retain(|n| n != nonce);
        matches!(entry, Some((p, expires)) if p == principal && now < expires)
    }
}

// ── Token & Sessions (AUTH-4.17, AUTH-4.23–4.25) ─────────────────────────

/// The opaque session token: 128 bits of fresh CSPRNG output, wire form 32
/// lowercase hex. `parse` admits ONLY what `to_wire` emits and the pair is
/// injective (AUTH-4.17). Compared exactly, never logged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Token([u8; SESSION_TOKEN_BYTES]);

impl Token {
    pub fn to_wire(&self) -> String {
        hex_lower(&self.0)
    }

    /// ONLY 32 lowercase hex; a value this refuses is NO token
    /// (AUTH-4.18) — it resolves `Guest(NoToken)`, nothing to close.
    pub fn parse(s: &str) -> Option<Token> {
        if s.len() != SESSION_TOKEN_BYTES * 2
            || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut raw = [0u8; SESSION_TOKEN_BYTES];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            raw[i] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
        }
        Some(Token(raw))
    }
}

/// One live session's binding: the M10 session, the named principal, and
/// the key that established it (`None` = bare bind).
#[derive(Debug, Clone)]
pub(crate) struct SessionEntry {
    pub sid: SessionId,
    pub principal: PrincipalId,
    pub key: Option<Fingerprint>,
}

/// A map lookup's three arms, constructed in ONE home so no call site can
/// mis-map them (AUTH-4.23).
pub(crate) enum Lookup {
    NoToken,
    Unknown,
    Found(SessionEntry),
}

/// The sessions store: token → entry, exclusion scoped to the map access —
/// `lookup` shared, `open`/`close` exclusive, no guard crossing `resolve`
/// (AUTH-4.24; RES-33). Process-lifetime, no cap, no TTL (AUTH-7.15's
/// declined knob — lazy eviction at presentation, `/session/close`, and
/// restart are the reclaim mechanisms, AUTH-1.53).
pub(crate) struct Sessions {
    map: parking_lot::RwLock<HashMap<Token, SessionEntry>>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions { map: parking_lot::RwLock::new(HashMap::new()) }
    }

    /// Mint a fresh token for `e`: [`SESSION_TOKEN_BITS`] of CSPRNG output
    /// per call (AUTH-4.23).
    pub fn open(&self, e: SessionEntry, rng: &mut impl CryptoRng) -> Token {
        let mut raw = [0u8; SESSION_TOKEN_BYTES];
        rng.fill_bytes(&mut raw);
        let token = Token(raw);
        self.map.write().insert(token.clone(), e);
        token
    }

    /// `None` ⇒ `NoToken`, miss ⇒ `Unknown`, hit ⇒ `Found` (by value — no
    /// borrow outlives the lookup).
    pub fn lookup(&self, t: Option<&Token>) -> Lookup {
        match t {
            None => Lookup::NoToken,
            Some(t) => match self.map.read().get(t) {
                None => Lookup::Unknown,
                Some(e) => Lookup::Found(e.clone()),
            },
        }
    }

    /// Returns the closed entry — the `sid` the M10 close needs, with no
    /// second lookup.
    pub fn close(&self, t: &Token) -> Option<SessionEntry> {
        self.map.write().remove(t)
    }
}

/// The resolved actor of one request (AUTH-4.25). The glue
/// closes-and-signals on `Unknown | EntryDead` ONLY; `NoToken` has nothing
/// to close; a `RequestRefused` entry lives untouched.
pub(crate) enum Actor {
    Guest(GuestReason),
    Principal(SessionEntry),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestReason {
    NoToken,
    Unknown,
    EntryDead,
    RequestRefused,
}

// ── bare_bind_allowed & resolve (AUTH-4.26–4.31) ─────────────────────────

/// The bare-bind predicate's three-valued answer; the MODE conjunct is
/// tested FIRST (AUTH-4.27) — mode is the monotone conjunct, so a cell
/// where both conjunct classes fail answers `ModeRefused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BareBind {
    Allowed,
    ModeRefused,
    RequestRefused,
}

/// AUTH-4.26 — the ONE home of the bare-bind rule: loopback peer, origin
/// header ok (absent ⇒ ok; present ⇒ parses AND in the BARE set; `null`
/// parses to nothing ⇒ refused), and not ENFORCING (`!claimed ||
/// local_trust` — bare binds are honored in UNCLAIMED and
/// CLAIMED-PERMISSIVE, never in ENFORCING).
pub(crate) fn bare_bind_allowed(
    cfg: &AuthConfig,
    peer: Peer,
    origin_hdr: Option<&str>,
    claimed: bool,
) -> BareBind {
    let enforcing = claimed && !cfg.local_trust;
    if enforcing {
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

/// AUTH-4.30 — the account a principal's keys are read from:
/// `BOOTSTRAP_PRINCIPAL` ↦ the claimant (None while unclaimed, so an
/// unclaimed board's 0 signs with nothing), else the principal's own
/// prefix; `None` for an unknown principal.
pub(crate) fn key_subject(
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
        Lookup::Found(entry) => match entry.key {
            Some(k) => {
                let live = key_subject(world, identity, entry.principal)
                    .is_some_and(|a| identity.key_set(&a).contains(&k));
                if live {
                    Actor::Principal(entry)
                } else {
                    Actor::Guest(GuestReason::EntryDead)
                }
            }
            None => match bare_bind_allowed(cfg, peer, origin_hdr, claimed) {
                BareBind::Allowed => Actor::Principal(entry),
                BareBind::ModeRefused => Actor::Guest(GuestReason::EntryDead),
                BareBind::RequestRefused => Actor::Guest(GuestReason::RequestRefused),
            },
        },
    }
}

// ── the handshake (AUTH-4.32–4.41, AUTH-6.2–6.5) ─────────────────────────

/// The two exact `POST /session` body forms (AUTH-6.2).
pub(crate) enum SessionBody {
    Bare { principal: PrincipalId },
    Signed { principal: PrincipalId, nonce: Nonce, origin: Origin, sig: [u8; 64] },
}

/// The handshake refusal — a unit struct: the reason is DESTROYED at the
/// return, so nothing a route marshals can leak it (AUTH-4.35). The wire
/// answer is the ONE code, `401 session_rejected`, byte-identical across
/// causes.
pub(crate) struct SessionRejected;

/// Parse the strict two-form body (AUTH-6.2, AUTH-6.3): the bare
/// `{"principal": n}` or the signed four-field form, all three signed
/// fields validated BEFORE anything burns — any failure is the 400
/// `malformed_session_request` and the nonce survives. `Err(detail)` is
/// the 400's detail text.
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
    let known: &[&str] = &["principal", "nonce", "origin", "sig"];
    if let Some(k) = m.keys().find(|k| !known.contains(&k.as_str())) {
        return Err(format!("unknown field '{k}'"));
    }
    let signed_fields =
        [m.get("nonce"), m.get("origin"), m.get("sig")].iter().filter(|f| f.is_some()).count();
    match signed_fields {
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
            Ok(SessionBody::Signed { principal, nonce, origin, sig })
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

/// AUTH-6.4 — the signed bytes: `framed(SESSION_TAG, [origin, nonce,
/// principal-as-shortest-decimal])` over the body's OWN strings; the
/// daemon canonicalizes NOTHING on this path.
pub(crate) fn session_payload(origin: &Origin, nonce_hex: &str, p: PrincipalId) -> Vec<u8> {
    framed(
        SESSION_TAG,
        &[origin.as_str().as_bytes(), nonce_hex.as_bytes(), p.0.to_string().as_bytes()],
    )
}

/// AUTH-4.32 — Ed25519 strict verification (`verify_strict` semantics);
/// false on an undecodable key or signature; never panics.
fn verify(key: &skep_identity::PublicKey, payload: &[u8], sig: &[u8; 64]) -> bool {
    let raw: &[u8] = key.raw();
    let Ok(raw32) = <[u8; 32]>::try_from(raw) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&raw32) else { return false };
    vk.verify_strict(payload, &Signature::from_bytes(sig)).is_ok()
}

/// AUTH-4.33 — try EVERY enrolled key in fingerprint order — no cutoff,
/// ever — returning the fingerprint alone.
fn find_signer(set: &KeySet, payload: &[u8], sig: &[u8; 64]) -> Option<Fingerprint> {
    set.enrolled().find(|(_, e)| verify(&e.key, payload, sig)).map(|(fp, _)| *fp)
}

/// The handshake (AUTH-4.36/4.37): the signed arm's pinned order — origin
/// set, take (burns), key subject, key set, payload, find_signer — and the
/// bare arm's one predicate. Every failure is the same unit refusal.
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
) -> Result<(PrincipalId, Option<Fingerprint>), SessionRejected> {
    let claimed = identity.claimant().is_some();
    match body {
        SessionBody::Bare { principal } => {
            match bare_bind_allowed(cfg, peer, origin_hdr, claimed) {
                BareBind::Allowed => Ok((principal, None)),
                _ => Err(SessionRejected),
            }
        }
        SessionBody::Signed { principal, nonce, origin, sig } => {
            // 2 — the signed set (the bare set until the claim's drop).
            if !signed_origins(cfg, claimed).contains(&origin) {
                return Err(SessionRejected);
            }
            // 3 — the burn: unknown, expired, wrong-principal, reused all
            // die here, and the entry is gone either way.
            if !challenges.take(&nonce, principal, now) {
                return Err(SessionRejected);
            }
            // 4/5 — the subject and its set.
            let Some(account) = key_subject(world, identity, principal) else {
                return Err(SessionRejected);
            };
            let set = identity.key_set(&account);
            if set.is_empty() {
                return Err(SessionRejected);
            }
            // 6/7 — the signature over the body's OWN strings.
            let payload = session_payload(&origin, &nonce.to_hex(), principal);
            match find_signer(set, &payload, &sig) {
                Some(fp) => Ok((principal, Some(fp))),
                None => Err(SessionRejected),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let t = Token([7; 16]);
        assert_eq!(Token::parse(&t.to_wire()), Some(t.clone()));
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
        assert!(!ch.take(&n, PrincipalId(8), now), "wrong principal refuses");
        assert!(!ch.take(&n, PrincipalId(7), now), "and the entry burned with it");
        let n2 = ch.issue(PrincipalId(7), now, &mut rng);
        assert!(!ch.take(&n2, PrincipalId(7), now + CHALLENGE_TTL), "expiry refuses");
        let n3 = ch.issue(PrincipalId(7), now, &mut rng);
        assert!(ch.take(&n3, PrincipalId(7), now + Duration::from_secs(1)));
        assert!(!ch.take(&n3, PrincipalId(7), now + Duration::from_secs(1)), "single use");
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
        assert!(!ch.take(&a, PrincipalId(1), now), "the oldest was evicted");
        assert!(ch.take(&b, PrincipalId(1), now));
        assert!(ch.take(&c, PrincipalId(1), now));
    }
}
