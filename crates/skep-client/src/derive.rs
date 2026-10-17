//! The read-derivations (`client.md` §1.1's `derive` row).
//!
//! Each is a pure function over board reads with no store among its inputs
//! — the mode off `/health`'s pair (AUTH-5.86), AUTH-5.65's pre-check in
//! both arms, the three-state key diagnosis at the set AUTH-5.21's walk
//! reaches (AUTH-4.30 (i); every unseeded account answers empty by law,
//! AUTH-6.19), the principal of an address (AUTH-6.37), and AUTH-5.66's
//! `closed` predicate. The one admitted read — the account's credential
//! records — is [`records`], behind `acting`.

use std::fmt;

use skep_identity::Fingerprint;

use crate::address::{parent_account, within_principal_depth, MAX_PRINCIPAL_COMPONENTS};
use crate::board::{Board, Health, KeySet, KeySetAnswer};
use crate::halt::{clipped, Halt};
use crate::origin::Origin;

#[cfg(feature = "acting")]
pub mod records;

/// The three modes, derived from the pair `/health` publishes.
///
/// A mode is never a field of it (AUTH-5.86; the negative pin: no `mode`
/// field, ever).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// `claimant == null`.
    Unclaimed,
    /// `claimant != null` with `local_trust == true`.
    ClaimedPermissive,
    /// `claimant != null` with `local_trust == false`.
    Enforcing,
}

impl Mode {
    /// Returns the mode — AUTH-5.86's one sentence over the pair.
    pub fn of(health: &Health) -> Mode {
        match (health.claimant(), health.local_trust()) {
            (None, _) => Mode::Unclaimed,
            (Some(_), true) => Mode::ClaimedPermissive,
            (Some(_), false) => Mode::Enforcing,
        }
    }

    /// Returns the mode's name as the design spells it.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Unclaimed => "UNCLAIMED",
            Mode::ClaimedPermissive => "CLAIMED-PERMISSIVE",
            Mode::Enforcing => "ENFORCING",
        }
    }
}

/// The mode as a person reads it: its name as the design spells it.
impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The walk (AUTH-5.21; AUTH-4.30 (i)'s client sentence).
///
/// It reads `key_set` at the account and, while that set is empty, at each
/// account above it in turn, taking the first whose set is not; the
/// terminus empty is the never-keyed state. Every input public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    /// The account asked about.
    pub account: String,
    /// The account whose set the walk reached.
    ///
    /// It is the one the principal authenticates against; `account` itself
    /// where the terminus is empty.
    pub set_account: String,
    /// That set.
    pub set: KeySet,
    /// Every account the walk read, upward from `account`.
    pub visited: Vec<String>,
}

impl Walk {
    /// Returns whether the terminus is empty — no set opens this account.
    pub fn terminus_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Returns whether the account opens by reference.
    ///
    /// Its own set is empty, a set above it reached.
    pub fn by_reference(&self) -> bool {
        self.set_account != self.account && !self.set.is_empty()
    }
}

/// Runs the walk from `account`.
///
/// The account lies within the namespace's principal depth, which no
/// conforming board names past; with a deeper one refused, the walk makes
/// at most [`MAX_PRINCIPAL_COMPONENTS`] reads and holds as many short
/// prefixes.
///
/// # Errors
///
/// An account one deeper is refused before the first read (`too_deep`); an
/// address answering `not_an_account` halts; and the reads' errors.
pub fn walk_to_set(board: &Board, account: &str) -> Result<Walk, Halt> {
    if !within_principal_depth(account) {
        return Err(too_deep(account));
    }
    let mut at = account.to_string();
    let mut visited = Vec::new();
    loop {
        visited.push(at.clone());
        let set = match board.key_set(&at)? {
            KeySetAnswer::Set(set) => set,
            KeySetAnswer::NotAnAccount => {
                return Err(Halt::face(
                    format!("{at} is not an account on this board"),
                    "`key_set` answered `not_an_account` (AUTH-6.19): the address names no account",
                    "check the principal, the account address or the board",
                ))
            }
        };
        if !set.is_empty() {
            return Ok(Walk { account: account.to_string(), set_account: at, set, visited });
        }
        match parent_account(&at) {
            Some(parent) => at = parent,
            // The terminus empty: the account's own address, whose set is
            // empty — the never-keyed state.
            None => return Ok(Walk { account: account.to_string(), set_account: account.to_string(), set, visited }),
        }
    }
}

/// Returns the face of an account deeper than the namespace delegates.
///
/// The account is named by the board (`principal_prefix`, a session's
/// account, ω's prefix), never by the person, so the fault is the board's:
/// the walk upward from it would climb one component a read and keep each
/// prefix. The account is named by its first 64 bytes alone.
pub(crate) fn too_deep(account: &str) -> Halt {
    Halt::face(
        format!("the board named an account deeper than any it can delegate: {}…", clipped(account, 64)),
        format!(
            "an account has at most {MAX_PRINCIPAL_COMPONENTS} components — the namespace refuses a deeper principal prefix as \
             `too_deep` (wire.md §Operations, `delegate`) — and this one has more"
        ),
        "this is a fault in the board, not in your keys; nothing was written",
    )
}

/// The three-state key diagnosis — `key_set` publishing both lists (AUTH-6.18).
///
/// It is one diagnosis shared by `verify`, `session`'s pre-check and
/// `enroll` (`client.md` §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDiagnosis {
    /// In `enrolled`, with the flag the fingerprint was enrolled under.
    Enrolled { anchor: bool },
    /// In `retired`: I4's permanent bar (AUTH-2.98).
    Retired { anchor: bool },
    /// In neither list: "this account's records do not list this key".
    ///
    /// It is AUTH-5.25 cell (iii).
    Neither,
}

impl KeyDiagnosis {
    /// Returns the diagnosis of `fp` against `set`.
    pub fn of(set: &KeySet, fp: &Fingerprint) -> KeyDiagnosis {
        if let Some(e) = set.enrolled(fp) {
            return KeyDiagnosis::Enrolled { anchor: e.anchor };
        }
        if let Some(r) = set.retired(fp) {
            return KeyDiagnosis::Retired { anchor: r.anchor };
        }
        KeyDiagnosis::Neither
    }
}

/// Where the key stands, as a person reads it.
///
/// It is the phrase a face completes after "this key stands".
impl fmt::Display for KeyDiagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyDiagnosis::Enrolled { anchor: true } => "enrolled as an anchor",
            KeyDiagnosis::Enrolled { anchor: false } => "enrolled as a device key",
            KeyDiagnosis::Retired { .. } => "retired",
            KeyDiagnosis::Neither => "in neither list",
        })
    }
}

/// Runs the origin arm (AUTH-5.24, first; AUTH-5.65).
///
/// The origin this client signs for the board must stand ∈
/// `/health.auth.signed_origins`.
///
/// # Errors
///
/// Where it does not, the origin state (AUTH-5.36 arm (1)'s content) with
/// its clearing acts by cell — never "sign in", never a retry.
pub fn origin_arm(signed: &Origin, health: &Health) -> Result<(), Halt> {
    if health.signed_origins().iter().any(|o| *o == signed.as_str()) {
        return Ok(());
    }
    let listed = health.signed_origins();
    let listed = if listed.is_empty() { "the signed list is EMPTY".to_string() } else { format!("the signed list is [{}]", listed.join(", ")) };
    Err(Halt::face(
        format!("this board does not accept signed sessions at this origin: {signed}"),
        format!(
            "{listed} (/health.auth.signed_origins, AUTH-6.14) — once claimed the signed arm reads the \
             configured origins alone (AUTH-4.3), so a board claimed with no `--origin`, a port change, \
             or a loopback alias dialed against another refuses every signed body forever"
        ),
        "the board's operator re-issues its configured origin for the port it is reachable at (`skepd \
         --origin`, AUTH-5.35), or address the board at an origin its signed list names; where this \
         board is your own dual-bound node, set the origin this client signs for it to the board's \
         configured override origin (AUTH-5.36's third act)",
    ))
}

/// AUTH-5.65's pre-check, both arms.
///
/// It runs ahead of every `/challenge` this client fetches: the origin arm
/// first (AUTH-5.24), then the address derived by `principal_prefix`
/// (AUTH-5.67 (2); `None` the delegation-never-committed cell), then the
/// key-set compare at the set AUTH-5.21's walk reaches. The diagnosis is
/// answered, not faced: the caller renders the three-state face for its own
/// site. The principal the reads were made for rides with them, so a
/// handshake over them opens as that principal and no other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreCheck {
    /// The `/health` answer the pre-check read.
    pub health: Health,
    /// The mode off that answer's pair.
    pub mode: Mode,
    /// The principal `n` the pre-check was made for.
    pub principal: u64,
    /// `principal_prefix(n)`.
    pub account: String,
    /// The walk from `account`.
    pub walk: Walk,
    /// The key's diagnosis at the set the walk reached.
    pub diagnosis: KeyDiagnosis,
}

/// Runs the pre-check for `principal` holding the key `fp`.
///
/// # Errors
///
/// In order: the `/health` read's errors; the origin arm's face; an
/// unregistered principal; and the walk's halts.
pub fn precheck(board: &Board, principal: u64, fp: &Fingerprint) -> Result<PreCheck, Halt> {
    let health = board.health()?;
    origin_arm(board.signed(), &health)?;
    let mode = Mode::of(&health);
    let Some(account) = board.principal_prefix(principal)? else {
        return Err(Halt::face(
            format!("principal {principal} is not a registered account on this board"),
            "`principal_prefix` answered null: the delegation that would have minted this principal's \
             account never committed on this board (AUTH-5.65's cell), or the number is another board's",
            "check the principal number and the board; a notebook's claimant is principal 1 unless \
             `skep claim --principal` named another",
        ));
    };
    let walk = walk_to_set(board, &account)?;
    let diagnosis = KeyDiagnosis::of(&walk.set, fp);
    Ok(PreCheck { health, mode, principal, account, walk, diagnosis })
}

/// Returns the principal seated at `addr`.
///
/// It is `effective_owner(addr).principal` taken where `prefix == addr`
/// (AUTH-6.37: the one allocation test); `None` where the address is not an
/// allocated seat — ω then names the seat above it, which is *not* this
/// address's principal.
///
/// # Errors
///
/// [`Board::effective_owner`]'s errors.
pub fn principal_of(board: &Board, addr: &str) -> Result<Option<u64>, Halt> {
    Ok(board.effective_owner(addr)?.filter(|o| o.prefix == addr).map(|o| o.principal))
}

/// The arms of AUTH-5.66's `closed` predicate.
///
/// The predicate is a pure function over the key this process already
/// holds and the two reads the pre-check already makes: re-handshake iff
/// that fingerprint stands enrolled in the set AUTH-5.21's walk reaches for
/// the derived address and the origin this client signs is answered for,
/// else halt — the key burned on the key arm, the origin state on the
/// origin arm. The store is not among its inputs: a predicate that re-read
/// the file would re-handshake out of the halt the burn's expected end
/// *is*. The handshake's own `403 prefix_blocked` is the third value's site
/// — the re-handshake it directs meets it — and is faced there (`Blocked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedArm {
    /// The key stands enrolled and the origin is answered for: re-handshake.
    ReHandshake,
    /// The key is not enrolled at the set: halt, the key burned.
    KeyBurned,
    /// The signed origin is not answered for: halt, the origin state.
    OriginState,
}

/// Returns the arm for a `closed` met by a process holding `loaded`.
pub fn on_closed(loaded: &Fingerprint, signed: &Origin, health: &Health, walk: &Walk) -> ClosedArm {
    if origin_arm(signed, health).is_err() {
        return ClosedArm::OriginState;
    }
    match KeyDiagnosis::of(&walk.set, loaded) {
        KeyDiagnosis::Enrolled { .. } => ClosedArm::ReHandshake,
        _ => ClosedArm::KeyBurned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::fake::{self, Fake};
    use serde_json::json;

    fn health(claimant: Option<&str>, local_trust: bool, signed: &[&str]) -> Health {
        let body = json!({"auth": {"claimant": claimant, "local_trust": local_trust, "origins": [], "signed_origins": signed}, "log_position": 3, "ok": true});
        Health { raw: body.to_string().into_bytes(), body }
    }

    /// AUTH-5.86 — the three names off the pair, one sentence.
    #[test]
    fn the_mode_derives_from_the_pair() {
        assert_eq!(Mode::of(&health(None, true, &[])), Mode::Unclaimed);
        assert_eq!(Mode::of(&health(None, false, &[])), Mode::Unclaimed);
        assert_eq!(Mode::of(&health(Some("1.0.1"), true, &[])), Mode::ClaimedPermissive);
        assert_eq!(Mode::of(&health(Some("1.0.1"), false, &[])), Mode::Enforcing);
        assert_eq!(Mode::ClaimedPermissive.to_string(), "CLAIMED-PERMISSIVE", "a mode displays as its name");
    }

    /// AUTH-5.24/5.36 — the origin arm names the origin state, never a retry.
    ///
    /// AUTH-5.66 — the `closed` predicate's three values.
    #[test]
    fn the_origin_arm_and_the_closed_predicate() {
        let signed = Origin::parse("http://127.0.0.1:8642").unwrap();
        assert!(origin_arm(&signed, &health(Some("1.0.1"), true, &["http://127.0.0.1:8642"])).is_ok());
        let halt = origin_arm(&signed, &health(Some("1.0.1"), true, &[])).unwrap_err();
        assert!(halt.to_string().contains("does not accept signed sessions at this origin"));
        assert_eq!(halt.exit_code(), 3);
        let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
        let empty = Walk { account: "1.0.1".into(), set_account: "1.0.1".into(), set: KeySet::default(), visited: vec![] };
        assert_eq!(on_closed(&fp, &signed, &health(Some("1.0.1"), true, &[]), &empty), ClosedArm::OriginState);
        assert_eq!(on_closed(&fp, &signed, &health(Some("1.0.1"), true, &["http://127.0.0.1:8642"]), &empty), ClosedArm::KeyBurned);
        assert_eq!(KeyDiagnosis::of(&KeySet::default(), &fp), KeyDiagnosis::Neither);
        let stands = |d: KeyDiagnosis| format!("this key stands {d}");
        assert_eq!(stands(KeyDiagnosis::Neither), "this key stands in neither list");
        assert_eq!(stands(KeyDiagnosis::Retired { anchor: true }), "this key stands retired");
        assert_eq!(stands(KeyDiagnosis::Enrolled { anchor: false }), "this key stands enrolled as a device key");
    }

    /// AUTH-5.66's predicate over its whole input.
    ///
    /// The loaded key enrolled as an anchor or as a device key, retired, or
    /// in neither list, each with the origin this client signs answered for
    /// or not: re-handshake iff the key stands enrolled and the origin is
    /// answered for, the origin state wherever it is not, the key burned
    /// otherwise.
    #[test]
    fn the_closed_predicate_re_handshakes_iff_the_key_stands_and_the_origin_answers() {
        use crate::board::{EnrolledKey, RetiredKey};
        let signed = Origin::parse("http://127.0.0.1:8642").unwrap();
        let key = skep_signature::HybridSigner::from_seed(skep_signature::TAG_MLDSA65_ED25519, &[3; 32]).expect("tag 1").public_key().clone();
        let fp = Fingerprint::of(&key);
        let enrolled = |anchor| KeySet { enrolled: vec![EnrolledKey { fingerprint: fp, key: key.clone(), anchor }], ..KeySet::default() };
        let retired = KeySet { retired: vec![RetiredKey { fingerprint: fp, anchor: false }], ..KeySet::default() };
        for (set, stands) in [(enrolled(true), true), (enrolled(false), true), (retired, false), (KeySet::default(), false)] {
            let walk = Walk { account: "1.0.1".into(), set_account: "1.0.1".into(), set, visited: vec![] };
            for listed in [true, false] {
                let answered: &[&str] = if listed { &["http://127.0.0.1:8642"] } else { &["https://board.example"] };
                let expected = match (listed, stands) {
                    (false, _) => ClosedArm::OriginState,
                    (true, true) => ClosedArm::ReHandshake,
                    (true, false) => ClosedArm::KeyBurned,
                };
                let diagnosis = KeyDiagnosis::of(&walk.set, &fp);
                assert_eq!(on_closed(&fp, &signed, &health(Some("1.0.1"), false, answered), &walk), expected, "the key {diagnosis}, the origin listed: {listed}");
            }
        }
    }

    /// Returns `1.0.1` deepened to `n` components, each added one a 1.
    ///
    /// # Panics
    ///
    /// Panics where `n` is under 3.
    fn deep(n: usize) -> String {
        format!("1.0.1{}", ".1".repeat(n - 3))
    }

    /// The namespace's depth holds the walk (wire.md §Operations, `delegate`).
    ///
    /// An account deeper than any board delegates — four million components,
    /// the eight megabytes a `principal_prefix` answer may carry inside the
    /// dialer's cap — is refused before its first read, its face naming no
    /// more than its first 64 bytes.
    #[test]
    fn a_walk_from_an_account_deeper_than_the_namespace_delegates_reads_nothing() {
        let halt = walk_to_set(&fake::board(&Fake::unread()), &deep(4_000_000)).expect_err("too deep");
        assert_eq!(halt.exit_code(), 3);
        let text = halt.to_string();
        assert!(text.contains("deeper than any it can delegate") && text.len() < 4096, "{}", clipped(&text, 512));
    }

    /// The walk climbs one account a read from the namespace's depth.
    ///
    /// From an account at that depth it reaches the top-level account — 62
    /// reads from 64 components — and keeps one prefix a read.
    #[test]
    fn the_walk_climbs_at_most_the_namespaces_depth() {
        let fake = Fake::new(|_| fake::json(200, json!({"as_of": 9, "enrolled": [], "resp": "key_set", "retired": []})));
        let walk = walk_to_set(&fake::board(&fake), &deep(64)).expect("a walk");
        assert!(walk.terminus_empty());
        assert_eq!((walk.visited.len(), fake.log().len()), (62, 62));
    }

    /// The pre-check holds the board's `principal_prefix` answer to the depth.
    ///
    /// It does so before it walks: `/health`, the prefix, and the halt.
    #[test]
    fn the_precheck_refuses_a_principal_prefix_past_the_bound() {
        let origin = fake::origin().as_str().to_string();
        let account = deep(4_000_000);
        let fake = Fake::new(move |req| match req.path.as_str() {
            "/health" => fake::json(200, json!({"auth": {"claimant": "1.0.1", "local_trust": false, "origins": [origin], "signed_origins": [origin]}, "log_position": 9})),
            _ => fake::json(200, json!({"addr": account, "as_of": 9, "resp": "addr"})),
        });
        let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
        let halt = precheck(&fake::board(&fake), 7, &fp).expect_err("too deep");
        assert!(halt.to_string().contains("deeper than any it can delegate"), "{}", clipped(&halt.to_string(), 512));
        assert_eq!(fake.log(), ["GET /health", "POST /op principal_prefix"]);
    }
}
