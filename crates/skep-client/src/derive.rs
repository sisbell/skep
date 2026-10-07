//! The read-derivations (`client.md` §1.1's `derive` row): each a pure
//! function over board reads with no store among its inputs — the MODE off
//! `/health`'s pair (AUTH-5.86), AUTH-5.65's pre-check in both arms, the
//! THREE-STATE key diagnosis at the set AUTH-5.21's walk reaches (AUTH-4.30
//! (i); every unseeded account answers EMPTY BY LAW, AUTH-6.19), the
//! principal of an address (AUTH-6.37), and AUTH-5.66's `closed` predicate.
//! The one admitted READ — the account's credential records — is
//! [`records`], behind `acting`.

use std::fmt;

use skep_identity::Fingerprint;

use crate::address::parent_account;
use crate::board::{Board, Health, KeySet, KeySetAnswer};
use crate::halt::Halt;
use crate::origin::Origin;

#[cfg(feature = "acting")]
pub mod records;

/// The three modes, DERIVED from the pair `/health` publishes and never a
/// field of it (AUTH-5.86; the negative pin: no `mode` field, ever).
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
    /// AUTH-5.86's one sentence over the pair.
    pub fn of(health: &Health) -> Mode {
        match (health.claimant(), health.local_trust()) {
            (None, _) => Mode::Unclaimed,
            (Some(_), true) => Mode::ClaimedPermissive,
            (Some(_), false) => Mode::Enforcing,
        }
    }

    /// The mode's name as the design spells it.
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

/// THE WALK (AUTH-5.21; AUTH-4.30 (i)'s client sentence): `key_set` at the
/// account and, while that set is EMPTY, at each account above it in turn,
/// taking the first whose set is not; the terminus EMPTY is the never-keyed
/// state. Every input public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    /// The account asked about.
    pub account: String,
    /// The account whose set the walk reached — the one the principal
    /// authenticates against; `account` itself where the terminus is empty.
    pub set_account: String,
    /// That set.
    pub set: KeySet,
    /// Every account the walk read, top-down from `account`.
    pub visited: Vec<String>,
}

impl Walk {
    /// Whether the terminus is EMPTY — no set opens this account.
    pub fn terminus_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Whether the account opens BY REFERENCE — its own set empty, a set
    /// above it reached.
    pub fn by_reference(&self) -> bool {
        self.set_account != self.account && !self.set.is_empty()
    }
}

/// Run the walk from `account`.
pub fn walk_to_set(board: &Board, account: &str) -> Result<Walk, Halt> {
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
            // The terminus EMPTY: the account's own address, whose set is
            // empty — the never-keyed state.
            None => return Ok(Walk { account: account.to_string(), set_account: account.to_string(), set, visited }),
        }
    }
}

/// THE THREE-STATE KEY DIAGNOSIS — `key_set` publishing both lists
/// (AUTH-6.18): ONE diagnosis shared by `verify`, `session`'s pre-check and
/// `enroll` (`client.md` §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDiagnosis {
    /// In `enrolled`, with the flag the fingerprint was enrolled under.
    Enrolled { anchor: bool },
    /// In `retired`: I4's permanent bar (AUTH-2.98).
    Retired { anchor: bool },
    /// In NEITHER list: "this account's records do not list this key"
    /// (AUTH-5.25 cell (iii)).
    Neither,
}

impl KeyDiagnosis {
    /// The diagnosis of `fp` against `set`.
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

/// Where the key stands, as a person reads it — the phrase a face completes
/// after "this key stands".
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

/// THE ORIGIN ARM (AUTH-5.24, FIRST; AUTH-5.65): the origin this client
/// SIGNS for the board ∈ `/health.auth.signed_origins`, else the ORIGIN
/// STATE (AUTH-5.36 arm (1)'s content) with its clearing acts by cell —
/// never "sign in", never a retry.
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

/// AUTH-5.65's PRE-CHECK, both arms, ahead of EVERY `/challenge` this
/// client fetches: the origin arm first (AUTH-5.24), then the address
/// DERIVED by `principal_prefix` (AUTH-5.67 (2); `None` the
/// delegation-never-committed cell), then the key-set compare at the set
/// AUTH-5.21's walk reaches. The diagnosis is answered, not faced: the
/// caller renders the three-state face for its own site. The principal the
/// reads were made for rides with them, so a handshake over them opens as
/// that principal and no other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreCheck {
    pub health: Health,
    pub mode: Mode,
    /// The principal `n` the pre-check was made for.
    pub principal: u64,
    /// `principal_prefix(n)`.
    pub account: String,
    pub walk: Walk,
    pub diagnosis: KeyDiagnosis,
}

/// Run the pre-check for `principal` holding the key `fp`.
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

/// The principal seated at `addr` — `effective_owner(addr).principal` taken
/// WHERE `prefix == addr` (AUTH-6.37: the one allocation test); `None` where
/// the address is not an allocated seat — ω then names the seat above it,
/// which is NOT this address's principal.
pub fn principal_of(board: &Board, addr: &str) -> Result<Option<u64>, Halt> {
    Ok(board.effective_owner(addr)?.filter(|o| o.prefix == addr).map(|o| o.principal))
}

/// AUTH-5.66's `closed` predicate, a pure function over the key THIS
/// PROCESS ALREADY HOLDS and the two reads the pre-check already makes:
/// re-handshake iff that fingerprint is in the set AUTH-5.21's walk reaches
/// for the derived address AND the origin this client signs is answered
/// for, else HALT — the key BURNED on the key arm, the ORIGIN STATE on the
/// origin arm. The STORE is not among its inputs: a predicate that re-read
/// the file would re-handshake out of the halt the burn's expected end IS.
/// The handshake's own `403 prefix_blocked` is the third value's SITE — the
/// re-handshake it directs meets it — and is faced there (`Blocked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedArm {
    ReHandshake,
    KeyBurned,
    OriginState,
}

/// The arm for a `closed` met by a process holding `loaded`.
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

    /// AUTH-5.24/5.36 — the origin arm names the ORIGIN STATE, never a
    /// retry; AUTH-5.66 — the `closed` predicate's three values.
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

    /// AUTH-5.66's predicate over its whole input — the loaded key enrolled
    /// as an anchor or as a device key, retired, or in neither list, each
    /// with the origin this client signs answered for or not: RE-HANDSHAKE
    /// iff the key stands enrolled and the origin is answered for, the
    /// ORIGIN STATE wherever it is not, the key BURNED otherwise.
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
}
