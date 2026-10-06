//! THE HEAD INVARIANT's ENUMERATION and THE BY-REFERENCE CONE (`client.md`
//! §4a.8 T0; §4a.2 R6; AUTH-5.59's head; AUTH-5.89): "every key act of the
//! holder's — an enrollment as well as a retirement — reaches every set of
//! the holder's own, and the board says which those are", AND THE
//! ENUMERATION IS A CLOSURE AND NEVER ONE LEVEL — `X` together with every
//! account whose honored genesis stands in the doc 1 of an account the
//! enumeration already holds and whose set holds the key the act names,
//! `X`'s doc 1 first, then each admitted account's, UNTIL NO ACCOUNT IS
//! ADDED, one `key_set` read per admitted account. The CONE is descended by
//! ADDRESS and never by record (AUTH RES-143): children under an account are
//! CONTIGUOUS and `next_account_prefix` names the frontier, each child's set
//! one `key_set` read and its principal one `effective_owner` read, a SEEDED
//! child STOPPING the descent (its genesis stands in a doc 1 the read
//! already took), the depth bounded by `MAX_PRINCIPAL_COMPONENTS`. The cost
//! is said as the walks count it (§4a.2 R6: the accounts walked are counted
//! on stderr while it runs, through the `Person`).

use serde_json::Value;
use skep_identity::Fingerprint;

use super::say;
use crate::address::{doc_1_of, document_of};
use crate::board::{frames, Board, KeySet, KeySetAnswer, T_ENROLL};
use crate::derive::principal_of;
use crate::halt::Halt;
use crate::person::Person;

/// `skep-namespace`'s `MAX_PRINCIPAL_COMPONENTS`, reproduced: a principal
/// prefix names a delegation path and is capped at 64 components — deeper
/// is `too_deep` (wire.md §Operations, `delegate`; `skep-namespace/src/
/// state.rs`'s constant, which this crate does not link, as `origin`
/// reproduces the daemon's grammar). `next_account_prefix` answers `null`
/// past it, so the cone's descent is bounded here and there alike.
pub const MAX_PRINCIPAL_COMPONENTS: usize = 64;

/// One account the closure admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub account: String,
    pub set: KeySet,
    /// The doc 1 its honored genesis stands in (`X`'s own, for `X`).
    pub genesis_home: String,
}

/// The closure's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closure {
    /// `X` first, then each admitted account in the order admitted.
    pub accounts: Vec<Admitted>,
    /// The board reads made.
    pub reads: usize,
}

/// The `to` slot's first address of a link, off `read_link`.
pub fn link_subject(board: &Board, link: &str) -> Result<Option<String>, Halt> {
    let lv = board.guest(&frames::read_link(link))?;
    Ok(lv["link"]["slots"]
        .as_array()
        .and_then(|s| s.get(1))
        .and_then(Value::as_array)
        .and_then(|to| to.first())
        .and_then(|span| span["start"].as_str())
        .map(str::to_string))
}

/// THE ENROLL LINKS homed in `home` — every genesis (and holder enrollment)
/// deposited into one doc 1, each with its subject — the enumeration's read.
pub fn enroll_links_homed(board: &Board, home: &str) -> Result<Vec<(String, String)>, Halt> {
    let v = board.guest(&frames::find_links_ftt_home(T_ENROLL, home))?;
    let mut out = Vec::new();
    for link in v["addrs"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if document_of(link).as_deref() != Some(home) {
            continue;
        }
        if let Some(subject) = link_subject(board, link)? {
            out.push((link.to_string(), subject));
        }
    }
    Ok(out)
}

/// THE CLOSURE for `key` from `x`, as AUTH-5.59's head defines it.
pub fn head_closure(board: &Board, person: &mut dyn Person, x: &str, key: &Fingerprint) -> Result<Closure, Halt> {
    let mut reads = 0usize;
    let set = match board.key_set(x)? {
        KeySetAnswer::Set(s) => s,
        KeySetAnswer::NotAnAccount => return Err(Halt::face(format!("{x} is not an account"), "`key_set` answered `not_an_account`", "check the account address")),
    };
    reads += 1;
    let mut accounts = vec![Admitted { account: x.to_string(), set, genesis_home: doc_1_of(x) }];
    let mut queue = vec![x.to_string()];
    while let Some(a) = queue.pop() {
        let home = doc_1_of(&a);
        let links = enroll_links_homed(board, &home)?;
        reads += 1 + links.len();
        for (_, subject) in links {
            if accounts.iter().any(|s| s.account == subject) {
                continue;
            }
            let KeySetAnswer::Set(set) = board.key_set(&subject)? else { continue };
            reads += 1;
            if set.enrolled(key).is_some() || set.retired(key).is_some() {
                say(person, "AUTH-5.59 (enumeration)", format!("admitted {subject}: its honored genesis stands in {home} and its set holds the key"));
                accounts.push(Admitted { account: subject.clone(), set, genesis_home: home.clone() });
                queue.push(subject);
            }
        }
        if reads.is_multiple_of(8) {
            say(person, "AUTH-5.59 (cost)", format!("{reads} reads so far, {} account(s) admitted", accounts.len()));
        }
    }
    Ok(Closure { accounts, reads })
}

/// One account of the cone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConeNode {
    pub account: String,
    pub principal: Option<u64>,
    /// Its own set is non-empty: a SEEDED child — the descent stops here.
    pub seeded: bool,
    pub set: KeySet,
    pub depth: usize,
}

/// The cone's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cone {
    /// Every account beneath the roots that opens by reference (its own set
    /// empty), and every seeded child the descent stopped at.
    pub nodes: Vec<ConeNode>,
    pub reads: usize,
}

/// THE BY-REFERENCE CONE beneath `roots`: the children of each account by
/// `next_account_prefix`'s frontier, each child's set one `key_set` read,
/// its principal one `effective_owner` read, a seeded child stopping the
/// descent, the depth bounded by [`MAX_PRINCIPAL_COMPONENTS`].
pub fn by_reference_cone(board: &Board, person: &mut dyn Person, roots: &[String]) -> Result<Cone, Halt> {
    let mut nodes = Vec::new();
    let mut reads = 0usize;
    let mut stack: Vec<(String, usize)> = roots.iter().map(|r| (r.clone(), r.split('.').count())).collect();
    while let Some((parent, depth)) = stack.pop() {
        if depth >= MAX_PRINCIPAL_COMPONENTS {
            say(person, "AUTH-5.89 (bound)", format!("the descent stops at {parent}: the depth bound ({MAX_PRINCIPAL_COMPONENTS} components) is reached"));
            continue;
        }
        let Some(frontier) = board.next_account_prefix(&parent)? else { continue };
        reads += 1;
        let Some(n) = frontier.rsplit('.').next().and_then(|c| c.parse::<u64>().ok()) else { continue };
        for k in 1..n {
            let child = format!("{parent}.{k}");
            let set = match board.key_set(&child)? {
                KeySetAnswer::Set(s) => s,
                KeySetAnswer::NotAnAccount => continue,
            };
            let principal = principal_of(board, &child)?;
            reads += 2;
            let seeded = !set.enrolled.is_empty();
            nodes.push(ConeNode { account: child.clone(), principal, seeded, set, depth: depth + 1 });
            if !seeded {
                stack.push((child, depth + 1));
            }
            if reads.is_multiple_of(8) {
                say(person, "AUTH-5.89 (cost)", format!("{reads} reads so far, {} account(s) walked beneath {}", nodes.len(), roots.join(", ")));
            }
        }
    }
    Ok(Cone { nodes, reads })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The depth bound is the daemon's constant, reproduced.
    #[test]
    fn the_depth_bound_is_sixty_four_components() {
        assert_eq!(MAX_PRINCIPAL_COMPONENTS, 64);
    }
}
