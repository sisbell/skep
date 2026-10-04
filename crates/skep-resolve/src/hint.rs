//! THE ROOT HINT (REG-3.1 to REG-3.3; REG-3.39, REG-3.40, REG-3.42; R5) —
//! the ENTIRE bootstrap surface: the registry root's endpoint URL(s) plus the
//! REALM ID — the genesis key-set fingerprint, and on a forked lineage the
//! fork point beside it — shipped with a client as ONE OVERRIDABLE CONFIG
//! VALUE and never a baked constant. The root's address lives in the hint
//! alone and on no board (REG-3.3): no key on any board can move what a
//! mirror resolves from. Every resolution a mirror performs is scoped to the
//! hint's realm by construction (REG-3.42): the id is compared at the base,
//! and a mismatch is REG-3.19's refusal, named.
//!
//! THE ONE LINE (the hint's one-line syntax, an interim pin): whitespace-
//! separated terms — one or more origins in the order they are tried, the
//! realm as `realm:<64 lowercase hex>`, and on a forked lineage the fork
//! point as `fork:<address>` (REG-3.40). Pointing a world at a forked
//! registry is editing this one line (REG-3.2).
//!
//! ```text
//! https://registry.example https://registry.example.net realm:9f2a…c41d
//! ```
//!
//! THE REALM ID's FORM (REG-3.39: "the FINGERPRINT of the registry root's
//! GENESIS key set — its initial set, never its living one"; AUTH-2.119: the
//! form is built on the framing rule, over the genesis set in FINGERPRINT
//! ORDER — RES-1 — under a tag the registry's design is to declare; an
//! interim pin here, the design having pinned no tag yet): SHA-256 over the
//! bytes `skep-realm-v1` then, per enrolled key of the genesis set in
//! ascending fingerprint order, the key's fingerprint as a four-byte
//! big-endian length and its thirty-two digest bytes — the framing rule's
//! layout, spelled here because the tag is not among the declared ones and a
//! foreign crate frames under none. Two implementers that frame or order the
//! set differently mint different realm ids and fail every check, which is
//! why the order is ruled and the form is stated once, here.

use std::fmt;

use sha2::{Digest, Sha256};
use skep_address::Address;
use skep_identity::Fingerprint;

use crate::origin::Origin;
use crate::parse_address;

/// The root hint — the one config value a resolver boots from (REG-3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootHint {
    /// The root's endpoint URL(s), in the order a mirror tries them; at
    /// least one.
    pub origins: Vec<Origin>,
    /// The realm id: the genesis key-set fingerprint (REG-3.39).
    pub realm: Fingerprint,
    /// The fork point on a forked lineage — the address of the fork's
    /// succession record (REG-3.40); EMPTY on an unforked lineage.
    pub fork_point: Option<Address>,
}

/// Why a line is no root hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintError {
    /// No origin term.
    NoOrigin,
    /// A term that is neither `realm:`, `fork:` nor a canonical origin.
    BadOrigin(String),
    /// No `realm:` term.
    NoRealm,
    /// A `realm:` term that is not 64 hex characters.
    BadRealm(String),
    /// A `fork:` term that is no address.
    BadForkPoint(String),
    /// A term given twice.
    Duplicate(&'static str),
}

impl fmt::Display for HintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HintError::NoOrigin => f.write_str("the hint names no origin"),
            HintError::BadOrigin(t) => write!(f, "'{t}' is no canonical origin"),
            HintError::NoRealm => f.write_str("the hint names no realm (realm:<64 hex>)"),
            HintError::BadRealm(t) => write!(f, "'{t}' is no realm id (64 hex characters)"),
            HintError::BadForkPoint(t) => write!(f, "'{t}' is no fork point (an address)"),
            HintError::Duplicate(term) => write!(f, "the {term} term is given twice"),
        }
    }
}

impl std::error::Error for HintError {}

impl RootHint {
    /// A hint from its parts: at least one origin.
    pub fn new(
        origins: Vec<Origin>,
        realm: Fingerprint,
        fork_point: Option<Address>,
    ) -> Result<RootHint, HintError> {
        if origins.is_empty() {
            return Err(HintError::NoOrigin);
        }
        Ok(RootHint { origins, realm, fork_point })
    }

    /// THE ONE LINE, parsed: origins, `realm:<hex>`, and `fork:<address>`
    /// where the lineage forked, in any order, whitespace-separated.
    pub fn parse(line: &str) -> Result<RootHint, HintError> {
        let mut origins = Vec::new();
        let mut realm = None;
        let mut fork_point = None;
        for term in line.split_whitespace() {
            if let Some(hex) = term.strip_prefix("realm:") {
                if realm.is_some() {
                    return Err(HintError::Duplicate("realm"));
                }
                realm = Some(Fingerprint::parse_hex(hex).ok_or_else(|| HintError::BadRealm(term.into()))?);
            } else if let Some(addr) = term.strip_prefix("fork:") {
                if fork_point.is_some() {
                    return Err(HintError::Duplicate("fork"));
                }
                fork_point =
                    Some(parse_address(addr).ok_or_else(|| HintError::BadForkPoint(term.into()))?);
            } else {
                origins.push(Origin::parse(term).ok_or_else(|| HintError::BadOrigin(term.into()))?);
            }
        }
        let realm = realm.ok_or(HintError::NoRealm)?;
        RootHint::new(origins, realm, fork_point)
    }
}

/// The one line, as [`RootHint::parse`] reads it back.
impl fmt::Display for RootHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for o in &self.origins {
            write!(f, "{o} ")?;
        }
        write!(f, "realm:{}", self.realm.to_hex())?;
        if let Some(fork) = &self.fork_point {
            write!(f, " fork:{fork}")?;
        }
        Ok(())
    }
}

/// THE REALM ID of a genesis set (REG-3.39; AUTH-2.119's order): the
/// fingerprints in ascending fingerprint order, hashed under the form the
/// module doc states. Total over any set, the empty one included.
pub fn realm_id(genesis: &[Fingerprint]) -> Fingerprint {
    let mut ordered: Vec<&Fingerprint> = genesis.iter().collect();
    ordered.sort();
    ordered.dedup();
    let mut hasher = Sha256::new();
    hasher.update(b"skep-realm-v1");
    for fp in ordered {
        hasher.update((fp.as_bytes().len() as u32).to_be_bytes());
        hasher.update(fp.as_bytes());
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Fingerprint::parse_hex(&hex).expect("a SHA-256 digest is 64 hex characters")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> Fingerprint {
        Fingerprint::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    /// The one line reads back as itself, with and without a fork point,
    /// and each malformed term is refused by name.
    #[test]
    fn the_one_line_parses_and_renders() {
        let line = format!("https://registry.example http://127.0.0.1:8642 realm:{}", fp(0xab).to_hex());
        let hint = RootHint::parse(&line).expect("a hint");
        assert_eq!(hint.origins.len(), 2);
        assert_eq!(hint.realm, fp(0xab));
        assert_eq!(hint.fork_point, None);
        assert_eq!(hint.to_string(), line);
        let forked = format!("{line} fork:1.0.1.0.1.0.2.9");
        let hint = RootHint::parse(&forked).expect("a forked hint");
        assert_eq!(hint.fork_point.as_ref().map(ToString::to_string).as_deref(), Some("1.0.1.0.1.0.2.9"));
        assert_eq!(hint.to_string(), forked);
        assert_eq!(RootHint::parse(&format!("realm:{}", fp(1).to_hex())), Err(HintError::NoOrigin));
        assert_eq!(RootHint::parse("https://registry.example"), Err(HintError::NoRealm));
        assert_eq!(RootHint::parse("https://registry.example realm:zz"), Err(HintError::BadRealm("realm:zz".into())));
        assert_eq!(
            RootHint::parse(&format!("registry.example realm:{}", fp(1).to_hex())),
            Err(HintError::BadOrigin("registry.example".into()))
        );
        assert_eq!(
            RootHint::parse(&format!("https://r.example realm:{} fork:1.0", fp(1).to_hex())),
            Err(HintError::BadForkPoint("fork:1.0".into()))
        );
        assert_eq!(
            RootHint::parse(&format!("https://r.example realm:{} realm:{}", fp(1).to_hex(), fp(2).to_hex())),
            Err(HintError::Duplicate("realm"))
        );
    }

    /// The realm id is over the SET: the same fingerprints in any order
    /// hash alike, a different set differently, and the empty set is a value.
    #[test]
    fn the_realm_id_is_order_free_and_set_sensitive() {
        let a = realm_id(&[fp(1), fp(2)]);
        assert_eq!(a, realm_id(&[fp(2), fp(1)]));
        assert_eq!(a, realm_id(&[fp(2), fp(1), fp(2)]), "a repeated fingerprint is one member");
        assert_ne!(a, realm_id(&[fp(1)]));
        assert_ne!(a, realm_id(&[fp(1), fp(3)]));
        assert_ne!(realm_id(&[]), realm_id(&[fp(1)]));
    }
}
