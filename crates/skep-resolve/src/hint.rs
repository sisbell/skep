//! THE ROOT HINT (REG-3.1 to REG-3.3; REG-3.39, REG-3.40, REG-3.42; R5) —
//! the ENTIRE bootstrap surface: the registry root's endpoint URL(s) plus the
//! REALM ID ([`RealmId`]) — the genesis fingerprint, and on a forked lineage
//! the fork point beside it — shipped with a client as ONE OVERRIDABLE CONFIG
//! VALUE and never a baked constant. The root's address lives in the hint
//! alone and on no board (REG-3.3): no key on any board can move what a
//! mirror resolves from. A mirror's resolutions are scoped by the realm check
//! at the base (REG-3.42), which compares the id's GENESIS FINGERPRINT
//! against the root's genesis set — a mismatch is REG-3.19's refusal, named;
//! the fork point rides in the hint and is compared by no check of this
//! crate.
//!
//! THE ONE LINE (the hint's one-line syntax, an interim pin): whitespace-
//! separated terms — one or more origins in the order they are tried, the
//! realm id's genesis fingerprint as `realm:<64 lowercase hex>`, and on a
//! forked lineage its fork point as `fork:<address>` (REG-3.40). Pointing a
//! world at a forked registry is editing this one line (REG-3.2).
//!
//! ```text
//! https://registry.example https://registry.example.net realm:9f2a…c41d
//! ```
//!
//! THE GENESIS FINGERPRINT'S FORM (REG-3.39: "the FINGERPRINT of the registry
//! root's GENESIS key set — its initial set, never its living one";
//! AUTH-2.119: the form is built on the framing rule, over the genesis set in
//! FINGERPRINT ORDER — RES-1 — under a tag the registry's design is to
//! declare; an interim pin here, the design having pinned no tag yet):
//! SHA-256 over the bytes `skep-realm-v1` then, per enrolled key of the
//! genesis set in ascending fingerprint order, the key's fingerprint as a
//! four-byte big-endian length and its thirty-two digest bytes — the framing
//! rule's layout, spelled here because the tag is not among the declared ones
//! and a foreign crate frames under none. Two implementers that frame or order
//! the set differently mint different genesis fingerprints and fail every
//! check, which is why the order is ruled and the form is stated once, here.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};
use skep_address::Address;
use skep_identity::Fingerprint;

use crate::origin::Origin;
use crate::parse_address;

/// THE REALM ID (REG-3.39, REG-3.40; R5): the GENESIS FINGERPRINT — the
/// fingerprint of the registry root's genesis key set, in the form the module
/// doc states ([`RealmId::genesis_fingerprint`]) — and, on a forked lineage,
/// the FORK POINT beside it, the address of the fork's succession record
/// (REG-3.49). Two lineages that share one genesis and differ in their fork
/// point are two realms; on an unforked lineage the genesis fingerprint is
/// the whole id. A realm keys a map — a node holding one mirror per realm —
/// by hash or by order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RealmId {
    /// The genesis fingerprint — the id's first half.
    pub genesis: Fingerprint,
    /// The fork point — the id's second half; `None` on an unforked lineage.
    pub fork_point: Option<Address>,
}

impl RealmId {
    /// THE GENESIS FINGERPRINT of a genesis set (REG-3.39; AUTH-2.119's
    /// order): the realm id's first half, and on an unforked lineage the
    /// whole id — the set's fingerprints in ascending fingerprint order,
    /// hashed under the form the module doc states. Total over any set, the
    /// empty one included.
    pub fn genesis_fingerprint(genesis_set: &[Fingerprint]) -> Fingerprint {
        let mut ordered: Vec<&Fingerprint> = genesis_set.iter().collect();
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
}

/// The root hint — the one config value a resolver boots from (REG-3.2).
///
/// Every hint comes through [`RootHint::new`] or the one line
/// ([`RootHint::parse`], or `str::parse`), so every hint holds an origin
/// and renders a line `parse` reads back as itself: its fields are read
/// through [`RootHint::origins`] and [`RootHint::realm`], and written by
/// nothing outside this module. The twin reads what the refusal below it
/// writes, the refusal's one difference the write:
///
/// ```
/// use skep_resolve::{RealmId, RootHint};
/// let line = format!("http://127.0.0.1:8642 realm:{}", RealmId::genesis_fingerprint(&[]).to_hex());
/// let hint: RootHint = line.parse().expect("a hint");
/// assert!(!hint.origins().is_empty());
/// assert_eq!(hint.to_string().parse::<RootHint>(), Ok(hint));
/// ```
/// ```compile_fail,E0616
/// use skep_resolve::{RealmId, RootHint};
/// let line = format!("http://127.0.0.1:8642 realm:{}", RealmId::genesis_fingerprint(&[]).to_hex());
/// let mut hint: RootHint = line.parse().expect("a hint");
/// hint.origins.clear();
/// assert_eq!(hint.to_string().parse::<RootHint>(), Ok(hint));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RootHint {
    origins: Vec<Origin>,
    realm: RealmId,
}

/// Why a line is no root hint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HintError {
    /// No origin term.
    NoOrigin,
    /// A term that is neither `realm:`, `fork:` nor a canonical origin.
    BadOrigin(String),
    /// No `realm:` term.
    NoRealm,
    /// A `realm:` term whose value is no genesis fingerprint — 64 hex
    /// characters.
    BadRealm(String),
    /// A `fork:` term that is no address.
    BadFork(String),
    /// The `realm:` term given twice.
    DuplicateRealm,
    /// The `fork:` term given twice.
    DuplicateFork,
}

impl fmt::Display for HintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HintError::NoOrigin => f.write_str("the hint names no origin"),
            HintError::BadOrigin(t) => write!(f, "'{t}' is no canonical origin"),
            HintError::NoRealm => f.write_str("the hint names no realm (realm:<64 hex>)"),
            HintError::BadRealm(t) => write!(f, "'{t}' is no genesis fingerprint (64 hex characters)"),
            HintError::BadFork(t) => write!(f, "'{t}' is no fork point (an address)"),
            HintError::DuplicateRealm => f.write_str("the realm term is given twice"),
            HintError::DuplicateFork => f.write_str("the fork term is given twice"),
        }
    }
}

impl std::error::Error for HintError {}

impl RootHint {
    /// A hint from its parts: at least one origin, and the realm id's two
    /// halves — the genesis fingerprint, and the fork point where the lineage
    /// forked.
    pub fn new(
        origins: Vec<Origin>,
        genesis: Fingerprint,
        fork_point: Option<Address>,
    ) -> Result<RootHint, HintError> {
        if origins.is_empty() {
            return Err(HintError::NoOrigin);
        }
        Ok(RootHint { origins, realm: RealmId { genesis, fork_point } })
    }

    /// The root's endpoint URL(s), in the order a mirror tries them — at
    /// least one.
    pub fn origins(&self) -> &[Origin] {
        &self.origins
    }

    /// The realm id: the genesis fingerprint, and the fork point on a forked
    /// lineage (REG-3.2, REG-3.40).
    pub fn realm(&self) -> &RealmId {
        &self.realm
    }

    /// THE ONE LINE, parsed: origins, `realm:<hex>`, and `fork:<address>`
    /// where the lineage forked, in any order, whitespace-separated.
    pub fn parse(line: &str) -> Result<RootHint, HintError> {
        let mut origins = Vec::new();
        let mut genesis = None;
        let mut fork_point = None;
        for term in line.split_whitespace() {
            if let Some(hex) = term.strip_prefix("realm:") {
                if genesis.is_some() {
                    return Err(HintError::DuplicateRealm);
                }
                genesis = Some(Fingerprint::parse_hex(hex).ok_or_else(|| HintError::BadRealm(term.into()))?);
            } else if let Some(addr) = term.strip_prefix("fork:") {
                if fork_point.is_some() {
                    return Err(HintError::DuplicateFork);
                }
                fork_point = Some(parse_address(addr).ok_or_else(|| HintError::BadFork(term.into()))?);
            } else {
                origins.push(Origin::parse(term).ok_or_else(|| HintError::BadOrigin(term.into()))?);
            }
        }
        let genesis = genesis.ok_or(HintError::NoRealm)?;
        RootHint::new(origins, genesis, fork_point)
    }
}

/// The one line through `str::parse`, as [`RootHint::parse`] reads it — the
/// form a generic caller reaches: a command's argument parser, an
/// environment reader, a config loader.
impl FromStr for RootHint {
    type Err = HintError;

    fn from_str(line: &str) -> Result<RootHint, HintError> {
        RootHint::parse(line)
    }
}

/// The one line, as [`RootHint::parse`] reads it back.
impl fmt::Display for RootHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for o in &self.origins {
            write!(f, "{o} ")?;
        }
        write!(f, "realm:{}", self.realm.genesis.to_hex())?;
        if let Some(fork) = &self.realm.fork_point {
            write!(f, " fork:{fork}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};

    use super::*;

    fn fp(byte: u8) -> Fingerprint {
        Fingerprint::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    /// The one line reads back as itself, with and without a fork point —
    /// through `parse` and `str::parse` alike — and each malformed term is
    /// refused by name, a term given twice by which. The two lines name two
    /// realms (REG-3.40): one genesis fingerprint, and a fork point on the
    /// one alone — two keys of a map, by hash and by order.
    #[test]
    fn the_one_line_parses_and_renders() {
        let line = format!("https://registry.example http://127.0.0.1:8642 realm:{}", fp(0xab).to_hex());
        let hint = RootHint::parse(&line).expect("a hint");
        assert_eq!(line.parse::<RootHint>(), Ok(hint.clone()), "str::parse reads the one line");
        assert_eq!(hint.origins.len(), 2);
        assert_eq!(hint.realm, RealmId { genesis: fp(0xab), fork_point: None });
        assert_eq!(hint.to_string(), line);
        let forked = format!("{line} fork:1.0.1.0.1.0.2.9");
        let forked_hint = RootHint::parse(&forked).expect("a forked hint");
        assert_eq!(forked_hint.realm.fork_point.as_ref().map(ToString::to_string).as_deref(), Some("1.0.1.0.1.0.2.9"));
        assert_eq!(forked_hint.to_string(), forked);
        assert_eq!(forked_hint.realm.genesis, hint.realm.genesis, "one genesis");
        assert_ne!(forked_hint.realm, hint.realm, "two realms");
        let realms = [hint.realm.clone(), forked_hint.realm.clone(), hint.realm.clone()];
        assert_eq!(realms.iter().collect::<HashSet<_>>().len(), 2, "two realms key two entries by hash");
        assert_eq!(realms.iter().collect::<BTreeSet<_>>().len(), 2, "and by order");
        assert_eq!(RootHint::parse(&format!("realm:{}", fp(1).to_hex())), Err(HintError::NoOrigin));
        assert_eq!(RootHint::parse("https://registry.example"), Err(HintError::NoRealm));
        assert_eq!(RootHint::parse("https://registry.example realm:zz"), Err(HintError::BadRealm("realm:zz".into())));
        assert_eq!(
            RootHint::parse(&format!("registry.example realm:{}", fp(1).to_hex())),
            Err(HintError::BadOrigin("registry.example".into()))
        );
        assert_eq!(
            RootHint::parse(&format!("https://r.example realm:{} fork:1.0", fp(1).to_hex())),
            Err(HintError::BadFork("fork:1.0".into()))
        );
        assert_eq!(
            RootHint::parse(&format!("https://r.example realm:{} realm:{}", fp(1).to_hex(), fp(2).to_hex())),
            Err(HintError::DuplicateRealm)
        );
        assert_eq!(
            format!("https://r.example realm:{} fork:1.0.1.0.1.0.2.9 fork:1.0.1.0.1.0.2.9", fp(1).to_hex()).parse::<RootHint>(),
            Err(HintError::DuplicateFork)
        );
    }

    /// THE ONE LINE in any order and any whitespace, as a file or an
    /// environment delivers it: every ordering of two origins, the realm term
    /// and the fork term reads to one realm and to the origins in the order
    /// the line gives them; and a trailing newline, tabs, runs of spaces and
    /// a `\r\n` are whitespace like a space, never part of a term.
    #[test]
    fn the_one_line_reads_in_any_order_and_any_whitespace() {
        let realm = RealmId { genesis: fp(7), fork_point: Some(parse_address("1.0.1.0.1.0.2.9").unwrap()) };
        let realm_term = format!("realm:{}", fp(7).to_hex());
        let terms: [&str; 4] = ["https://a.example", "https://b.example", &realm_term, "fork:1.0.1.0.1.0.2.9"];
        let mut orderings = 0;
        for i in 0..4 {
            for j in (0..4).filter(|&j| j != i) {
                for k in (0..4).filter(|&k| k != i && k != j) {
                    let l = 6 - i - j - k;
                    let line = [terms[i], terms[j], terms[k], terms[l]].join(" ");
                    let hint = RootHint::parse(&line).unwrap_or_else(|e| panic!("{line}: {e}"));
                    assert_eq!(hint.realm, realm, "{line}");
                    let origins: Vec<&str> = [i, j, k, l].into_iter().filter(|&t| t < 2).map(|t| terms[t]).collect();
                    assert_eq!(hint.origins.iter().map(Origin::as_str).collect::<Vec<_>>(), origins, "{line}");
                    orderings += 1;
                }
            }
        }
        assert_eq!(orderings, 24);
        let bare = RootHint::parse(&terms.join(" ")).expect("a hint");
        for line in [
            format!("{}\n", terms.join(" ")),
            format!("\t{}\t \t{}  {}\t{}  ", terms[0], terms[1], realm_term, terms[3]),
            format!("{}\r\n{}\r\n{}\r\n{}\r\n", terms[0], terms[1], realm_term, terms[3]),
        ] {
            assert_eq!(RootHint::parse(&line), Ok(bare.clone()), "{line:?}");
        }
    }

    /// THE GENESIS FINGERPRINT'S FORM, as the module doc states it and no
    /// other: SHA-256 over `skep-realm-v1`, then each fingerprint of the set
    /// in ascending order, a four-byte big-endian length before its
    /// thirty-two bytes — the empty set's the tag's hash alone.
    #[test]
    fn the_genesis_fingerprint_is_the_form_the_module_doc_states() {
        let stated = |set: &[Fingerprint]| -> [u8; 32] {
            let mut bytes = b"skep-realm-v1".to_vec();
            for member in set {
                bytes.extend_from_slice(&32u32.to_be_bytes());
                bytes.extend_from_slice(member.as_bytes());
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&Sha256::digest(&bytes));
            digest
        };
        assert_eq!(RealmId::genesis_fingerprint(&[]).as_bytes(), &stated(&[]), "the empty set");
        assert_eq!(RealmId::genesis_fingerprint(&[fp(2), fp(1)]).as_bytes(), &stated(&[fp(1), fp(2)]), "in ascending order");
    }

    /// The genesis fingerprint is over the SET: the same fingerprints in any
    /// order hash alike, a different set differently, and the empty set is a
    /// value.
    #[test]
    fn the_genesis_fingerprint_is_order_free_and_set_sensitive() {
        let of = RealmId::genesis_fingerprint;
        let a = of(&[fp(1), fp(2)]);
        assert_eq!(a, of(&[fp(2), fp(1)]));
        assert_eq!(a, of(&[fp(2), fp(1), fp(2)]), "a repeated fingerprint is one member");
        assert_ne!(a, of(&[fp(1)]));
        assert_ne!(a, of(&[fp(1), fp(3)]));
        assert_ne!(of(&[]), of(&[fp(1)]));
    }
}
