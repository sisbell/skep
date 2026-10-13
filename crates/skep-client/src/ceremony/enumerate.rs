//! THE HEAD INVARIANT's ENUMERATION and THE BY-REFERENCE CONE (`client.md`
//! §4a.8 T0; §4a.2 R6; AUTH-5.59's head; AUTH-5.89): "every key act of the
//! holder's — an enrollment as well as a retirement — reaches every set of
//! the holder's own, and the board says which those are", AND THE
//! ENUMERATION IS A CLOSURE AND NEVER ONE LEVEL — `X` together with every
//! account whose honored genesis stands in the doc 1 of an account the
//! enumeration already holds and whose set holds the key the act names,
//! `X`'s doc 1 first, then each admitted account's, UNTIL NO ACCOUNT IS
//! ADDED, one `key_set` read per admitted account — a subject the doc 1s
//! name more than once read once. The CONE is descended by ADDRESS and never
//! by record (AUTH RES-143): children under an account are CONTIGUOUS and
//! `next_account_prefix` names the frontier — a child of that account, or
//! the walk halts — each child's set one `key_set` read, a SEEDED child
//! STOPPING the descent (its genesis stands in a doc 1 the read already
//! took), the depth bounded by `MAX_PRINCIPAL_COMPONENTS`. The cost is said
//! as the walks count it (§4a.2 R6: the accounts walked are counted on
//! stderr while it runs, through the `Person`).

use std::collections::HashSet;

use skep_identity::Fingerprint;

use super::say;
use crate::address::{doc_1_of, document_of, MAX_PRINCIPAL_COMPONENTS};
use crate::board::{answers, frames, Board, KeySet, KeySetAnswer, T_ENROLL};
use crate::halt::{clipped, Halt};
use crate::person::Person;

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
    Ok(answers::link_to(&lv).map(str::to_string))
}

/// THE ENROLL LINKS homed in `home` — every genesis (and holder enrollment)
/// deposited into one doc 1, each with its subject — the enumeration's read.
pub fn enroll_links_homed(board: &Board, home: &str) -> Result<Vec<(String, String)>, Halt> {
    let v = board.guest(&frames::find_links_ftt_home(T_ENROLL, home))?;
    let mut out = Vec::new();
    for link in answers::addrs(&v) {
        if document_of(link).as_deref() != Some(home) {
            continue;
        }
        if let Some(subject) = link_subject(board, link)? {
            out.push((link.to_string(), subject));
        }
    }
    Ok(out)
}

/// THE CLOSURE for `key` from `x`, as AUTH-5.59's head defines it: each
/// subject a genesis names read once, whichever doc 1 names it again.
pub fn head_closure(board: &Board, person: &mut dyn Person, x: &str, key: &Fingerprint) -> Result<Closure, Halt> {
    let mut reads = 0usize;
    let set = match board.key_set(x)? {
        KeySetAnswer::Set(s) => s,
        KeySetAnswer::NotAnAccount => return Err(Halt::face(format!("{x} is not an account"), "`key_set` answered `not_an_account`", "check the account address")),
    };
    reads += 1;
    let mut accounts = vec![Admitted { account: x.to_string(), set, genesis_home: doc_1_of(x) }];
    let mut seen: HashSet<String> = HashSet::from([x.to_string()]);
    let mut queue = vec![x.to_string()];
    while let Some(a) = queue.pop() {
        let home = doc_1_of(&a);
        let links = enroll_links_homed(board, &home)?;
        reads += 1 + links.len();
        for (_, subject) in links {
            if !seen.insert(subject.clone()) {
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
    /// Its own set is non-empty: a SEEDED child — the descent stops here.
    pub seeded: bool,
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
/// `next_account_prefix`'s frontier ([`frontier_children`]), each child's set
/// one `key_set` read, a seeded child stopping the descent, the depth bounded
/// by [`MAX_PRINCIPAL_COMPONENTS`].
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
        for k in 1..frontier_children(&parent, &frontier)? {
            let child = format!("{parent}.{k}");
            let set = match board.key_set(&child)? {
                KeySetAnswer::Set(s) => s,
                KeySetAnswer::NotAnAccount => continue,
            };
            reads += 1;
            let seeded = !set.enrolled.is_empty();
            nodes.push(ConeNode { account: child.clone(), seeded });
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

/// The frontier's ordinal beneath `parent` — `n` where `next_account_prefix`
/// answered `{parent}.{n}`, `n` a natural from 1 in its one spelling — the
/// children `1 .. n` standing before it (wire.md §Namespace: children under
/// an account are contiguous). A frontier naming no child of `parent` is no
/// answer the namespace gives: the walk halts on it rather than count
/// children of another account.
fn frontier_children(parent: &str, frontier: &str) -> Result<u64, Halt> {
    let n = frontier
        .strip_prefix(parent)
        .and_then(|rest| rest.strip_prefix('.'))
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0'))
        .and_then(|n| n.parse::<u64>().ok());
    n.ok_or_else(|| {
        Halt::face(
            format!("the board's frontier beneath {parent} names no child of it"),
            format!(
                "`next_account_prefix({parent})` answered `{}`, where the namespace answers the next delegable child, `{parent}.<n>` with `n` a natural from 1",
                clipped(frontier, 64)
            ),
            "this is a fault in the board, not in your keys; nothing was written",
        )
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::board::fake::{self, Fake};
    use crate::person::scripted::Scripted;

    /// A frontier answer that names no child of the account walked —
    /// another account's address, a top-of-range ordinal under it — halts
    /// the cone after the one read that met it, its children never counted.
    #[test]
    fn a_frontier_that_names_no_child_of_the_parent_is_refused() {
        for frontier in ["9.18446744073709551615", "1.0.10.3", "1.0.1.0", "1.0.1.03", "1.0.1.18446744073709551616"] {
            let fake = Fake::new(move |_| fake::json(200, json!({"addr": frontier, "as_of": 9, "resp": "addr"})));
            let halt = by_reference_cone(&fake::board(&fake), &mut Scripted::new(Vec::new()), &["1.0.1".to_string()]).expect_err(frontier);
            assert!(halt.to_string().contains("names no child of it"), "{frontier}: {halt}");
            assert_eq!(fake.log(), ["POST /op next_account_prefix"], "{frontier}");
        }
    }

    /// The cone reads each child's set once and its seat never: three
    /// children beneath `1.0.1`, each opening by reference, cost the
    /// frontier, three `key_set` reads and each child's own frontier.
    #[test]
    fn the_cone_reads_each_child_once() {
        let fake = Fake::new(|req| {
            let f = fake::frame(req);
            match f["op"].as_str() {
                Some("next_account_prefix") => {
                    let addr = if f["parent"] == "1.0.1" { json!("1.0.1.4") } else { json!(format!("{}.1", f["parent"].as_str().unwrap())) };
                    fake::json(200, json!({"addr": addr, "as_of": 9, "resp": "addr"}))
                }
                Some("key_set") => fake::json(200, json!({"as_of": 9, "enrolled": [], "resp": "key_set", "retired": []})),
                other => panic!("the cone sends no {other:?}"),
            }
        });
        let cone = by_reference_cone(&fake::board(&fake), &mut Scripted::new(Vec::new()), &["1.0.1".to_string()]).expect("a cone");
        assert_eq!(cone.nodes.iter().map(|n| (n.account.as_str(), n.seeded)).collect::<Vec<_>>(), [("1.0.1.1", false), ("1.0.1.2", false), ("1.0.1.3", false)]);
        assert_eq!(fake.log().len(), 7, "{:?}", fake.log());
        assert!(!fake.log().iter().any(|l| l.ends_with("effective_owner")), "{:?}", fake.log());
    }

    /// The closure reads a subject's set once, whichever doc 1 names it
    /// again: `1.0.2` named under `1.0.1`'s doc 1 and again under an
    /// admitted account's is one `key_set` read.
    #[test]
    fn the_closure_reads_each_subject_once() {
        let key = crate::sign::signer_from_seed(&[5; 32]).public_key().clone();
        let fp = Fingerprint::of(&key);
        let holding = json!({"as_of": 9, "resp": "key_set", "retired": [], "enrolled": [{"alg": key.alg(), "key": key.to_hex(), "fingerprint": fp.to_hex(), "anchor": false}]});
        let empty = json!({"as_of": 9, "enrolled": [], "resp": "key_set", "retired": []});
        // `1.0.1`'s doc 1 homes geneses of `1.0.3` (holding the key) and
        // `1.0.2` (not); `1.0.3`'s doc 1 names `1.0.2` again.
        let fake = Fake::new(move |req| {
            let f = fake::frame(req);
            match f["op"].as_str() {
                Some("key_set") => fake::json(200, if f["account"] == "1.0.2" { empty.clone() } else { holding.clone() }),
                Some("find_links_ftt") => {
                    let addrs = match f["q"]["home"][0]["start"].as_str() {
                        Some("1.0.1.0.1") => json!(["1.0.1.0.1.0.2.1", "1.0.1.0.1.0.2.2"]),
                        Some("1.0.3.0.1") => json!(["1.0.3.0.1.0.2.1"]),
                        _ => json!([]),
                    };
                    fake::json(200, json!({"addrs": addrs, "as_of": 9, "resp": "addrs"}))
                }
                Some("read_link") => {
                    let to = match f["a"].as_str() {
                        Some("1.0.1.0.1.0.2.1") => "1.0.3",
                        _ => "1.0.2",
                    };
                    fake::json(200, json!({"as_of": 9, "resp": "link_value", "link": {"slots": [[], [{"start": to, "width": "0.0.1"}], []]}}))
                }
                other => panic!("the closure sends no {other:?}"),
            }
        });
        let closure = head_closure(&fake::board(&fake), &mut Scripted::new(Vec::new()), "1.0.1", &fp).expect("a closure");
        assert_eq!(closure.accounts.iter().map(|a| a.account.as_str()).collect::<Vec<_>>(), ["1.0.1", "1.0.3"]);
        let sent = fake.sent.lock().unwrap();
        let reads_of = |account: &str| sent.iter().filter(|(_, r)| fake::frame(r)["op"] == "key_set" && fake::frame(r)["account"] == account).count();
        assert_eq!((reads_of("1.0.1"), reads_of("1.0.2"), reads_of("1.0.3")), (1, 1, 1));
    }
}
