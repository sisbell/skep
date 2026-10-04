//! THE WALK (REG-3.7 to REG-3.9; REG-1.10, REG-1.11; R5 (l); R2 (d)) —
//! `1.5` → (endpoint, key set) by ONE link: the binding record, resolved
//! under the many-into-one rule, names 1.5's registry-board account; that
//! account's fold gives the current keys and its own records give the
//! endpoint. Answered entirely from the mirror and the registry board, with
//! no runtime dependency on any other party (REG-3.9).
//!
//! `resolve(prefix)`: the binding from the index — read once at the build,
//! never derived at the resolve (REG-3.24) — then the account, its key set
//! as of the mirror's head, and its CURRENT endpoint: the latest honored
//! deposit on the active view of the account's doc 1, a nullified one gone
//! and the one before it standing (REG-1.10, REG-1.11). The endpoint's
//! members are then judged in the org's order ([`crate::origin`]) and the
//! answer is one of the named states ([`crate::state::Resolution`]). A depth
//! address — `1.5.3` — whose own prefix no binding names resolves to its
//! PARENT's standing and THE HOP NOT MADE (REG-3.82): the subnode's binding
//! is on org 1.5's board, a second mirror over a second hint, and the hop
//! is the caller's.
//!
//! THE GUEST-READING RESOLVE (REG-3.24, REG-3.33): a reader holding no
//! mirror answers a prefix by SCANNING — every binding link of the board by
//! its class, each link read, each atom fetched — inside the design and
//! outside the availability claim, exactly as available as the root. It
//! holds no positions, so no record it reads can be judged as of one: its
//! verdicts are UNDETERMINABLE HERE. Built here to be PRICED
//! ([`GuestCost`]), never to be the hot-loop reader.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{doc_1_of, Enrolled, PublicKey};
use skep_registry::{parse, t_binding, t_endpoint, Body, BodyKind};

use crate::http::Board;
use crate::index::Index;
use crate::mirror::{Mirror, MirrorError};
use crate::origin::{walk_members, MemberOutcome, NameResolver, Transports};
use crate::parse_address;
use crate::state::{BindingRecord, EndpointRecord, Judged, Resolution, Unreachable, Verdict};

/// RESOLVE `prefix` off `mirror` (REG-3.7 to REG-3.9): the walk's answer as
/// a named state. `names` is this resolver's own resolution of a host name
/// (REG-3.35) and `transports` what it can dial (REG-3.34 as RES-28 amends
/// it).
pub fn resolve(
    mirror: &mut Mirror,
    prefix: &Address,
    names: &dyn NameResolver,
    transports: &Transports,
) -> Result<Resolution, MirrorError> {
    let Some(standing) = mirror.index().standing(prefix) else {
        // A depth address whose parent this board binds: the hop not made.
        if let Some(parent) = mirror.index().longest_bound_prefix(prefix) {
            let parent = resolve(mirror, &parent, names, transports)?;
            return Ok(Resolution::HopNotMade { prefix: prefix.clone(), parent: Box::new(parent) });
        }
        return Ok(Resolution::Unregistered { prefix: prefix.clone() });
    };
    let Some(account) = standing.current.record.account.clone() else {
        return Ok(Resolution::RetiredWithHistory { standing, successor: None });
    };
    let keys = mirror.keys_at_head(&account)?.unwrap_or_default();
    let home = doc_1_of(&account);
    let endpoint = mirror.index().current_endpoint(&home).cloned();
    Ok(face_of(standing, keys, endpoint, mirror.index().any_honored_endpoint(&home), names, transports))
}

/// The face a standing, its keys and its current endpoint render (REG-3.80;
/// REG-3.34's one precedence over the members).
fn face_of(
    standing: crate::state::Standing,
    keys: Vec<Enrolled>,
    endpoint: Option<Judged<EndpointRecord>>,
    any_honored: bool,
    names: &dyn NameResolver,
    transports: &Transports,
) -> Resolution {
    let Some(endpoint) = endpoint else {
        let cause = if any_honored { Unreachable::NullifiedLast } else { Unreachable::NoEndpointYet };
        return Resolution::BoundButUnreachable { standing, keys, endpoint: None, cause, members: Vec::new() };
    };
    let walk = walk_members(&endpoint.record.origins, names, transports);
    if let Some(dial) = walk.dial {
        return Resolution::Bound { standing, keys, endpoint, dial, members: walk.outcomes };
    }
    // No member would dial: the FIRST member's outcome is the face's.
    match walk.outcomes.first().cloned() {
        Some(MemberOutcome::Refused { member, term }) => {
            Resolution::UnreachableByPolicy { standing, keys, endpoint, member, term, members: walk.outcomes }
        }
        Some(MemberOutcome::NotDialed { origin, kind }) => Resolution::DialNotMade {
            standing,
            keys,
            endpoint,
            member: origin.as_str().to_string(),
            kind,
            members: walk.outcomes,
        },
        Some(MemberOutcome::Dead { origin }) => Resolution::BoundButUnreachable {
            standing,
            keys,
            endpoint: Some(endpoint),
            cause: Unreachable::DeadOrigin { member: origin.as_str().to_string() },
            members: walk.outcomes,
        },
        // A dial would have been taken above; an endpoint body carries at
        // least one member, so this arm has no population.
        Some(MemberOutcome::WouldDial { .. }) | None => Resolution::BoundButUnreachable {
            standing,
            keys,
            endpoint: Some(endpoint),
            cause: Unreachable::NoEndpointYet,
            members: walk.outcomes,
        },
    }
}

/// What the guest-reading resolve cost (the investigation §3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestCost {
    /// Binding links the class scan listed.
    pub bindings_scanned: u64,
    /// Atoms read.
    pub atoms_read: u64,
    /// Wire reads made, every kind.
    pub reads: u64,
    /// Wall time.
    pub time: Duration,
}

/// THE GUEST-READING RESOLVE of `prefix` with NO mirror (REG-3.24, REG-3.33):
/// every binding link of the board by its class (`window_ftt` over the
/// binding's type, paged), each read, each atom fetched by its head position
/// and parsed; the prefix's bindings in their home's link order (journal
/// order within one home); the account's live key set; its endpoint
/// deposits by the same scan over its doc 1; the retraction of each by its
/// own retraction link. Every verdict UNDETERMINABLE HERE: no position is
/// held to judge a record as of. Answers the face and the cost.
pub fn guest_resolve(
    board: &Board,
    prefix: &Address,
    names: &dyn NameResolver,
    transports: &Transports,
) -> Result<(Resolution, GuestCost), MirrorError> {
    let t = Instant::now();
    let reads_before = board.reads().total();
    let mut cost = GuestCost::default();
    let mut index = Index::new();
    // Every binding link on the board, by its class.
    let mut links = scan_class(board, t_binding(), None)?;
    cost.bindings_scanned = links.len() as u64;
    links.sort_by_key(|a| a.tumbler().iter().cloned().collect::<Vec<_>>());
    for link in &links {
        if let Some((home, from, to)) = read_link(board, link)? {
            if let Some(text) = atom_at_head(board, &home, &from)? {
                cost.atoms_read += 1;
                if let Ok(record) = parse(BodyKind::Binding, text.as_bytes()) {
                    if let Body::Binding(b) = record.body {
                        if let Some(p) = parse_address(&b.prefix) {
                            index.fold_binding(Judged {
                                position: 0,
                                link: link.clone(),
                                home,
                                record: BindingRecord {
                                    prefix: p,
                                    account: to.first().cloned(),
                                    replaces: b.replaces.as_deref().and_then(parse_address),
                                    honored: false,
                                },
                                verdict: Verdict::UndeterminableHere,
                            });
                        }
                    }
                }
            }
        }
    }
    let finish = |cost: &mut GuestCost| {
        cost.reads = board.reads().total() - reads_before;
        cost.time = t.elapsed();
    };
    let Some(standing) = index.standing(prefix) else {
        finish(&mut cost);
        return Ok((Resolution::Unregistered { prefix: prefix.clone() }, cost));
    };
    let Some(account) = standing.current.record.account.clone() else {
        finish(&mut cost);
        return Ok((Resolution::RetiredWithHistory { standing, successor: None }, cost));
    };
    // The account's live key set and its endpoint deposits.
    let keys = live_keys(board, &account)?;
    let home = doc_1_of(&account);
    let mut deposits = scan_class(board, t_endpoint(), Some(&home))?;
    deposits.sort_by_key(|a| a.tumbler().iter().cloned().collect::<Vec<_>>());
    let retraction = parse_address("1.1.0.1.0.1.0.1.5").expect("the retraction class");
    for link in &deposits {
        if let Some((dep_home, from, _)) = read_link(board, link)? {
            if dep_home != home {
                continue;
            }
            if let Some(text) = atom_at_head(board, &dep_home, &from)? {
                cost.atoms_read += 1;
                if let Ok(record) = parse(BodyKind::Endpoint, text.as_bytes()) {
                    if let Body::Endpoint(e) = record.body {
                        let honored = index.fold_endpoint(Judged {
                            position: 0,
                            link: link.clone(),
                            home: dep_home,
                            record: EndpointRecord {
                                origins: e.origins,
                                replaces: e.replaces.as_deref().and_then(parse_address),
                                honored: false,
                                nullified: false,
                            },
                            verdict: Verdict::UndeterminableHere,
                        });
                        if honored && retracted(board, link, &retraction)? {
                            index.nullify(link);
                        }
                    }
                }
            }
        }
    }
    let endpoint = index.current_endpoint(&home).cloned();
    let any = index.any_honored_endpoint(&home);
    finish(&mut cost);
    Ok((face_of(standing, keys, endpoint, any, names, transports), cost))
}

/// Every link of type `ty` on the board, by `window_ftt` paged; `home`
/// constrains the home where given.
fn scan_class(board: &Board, ty: &Address, home: Option<&Address>) -> Result<Vec<Address>, MirrorError> {
    let mut out = Vec::new();
    let mut cur = Value::Null;
    loop {
        let home_spec = match home {
            Some(h) => json!([unit_span_json(h)]),
            None => json!("any"),
        };
        let v = board.op_ok(&json!({
            "op": "window_ftt", "cur": cur, "n": 256,
            "q": { "home": home_spec, "from": "any", "to": "any", "ty": [unit_span_json(ty)] },
        }))?;
        let window = &v["window"];
        for a in window["batch"].as_array().into_iter().flatten() {
            if let Some(addr) = a.as_str().and_then(parse_address) {
                out.push(addr);
            }
        }
        if window["exhausted"].as_bool().unwrap_or(true) {
            break;
        }
        cur = window["next"].clone();
    }
    Ok(out)
}

/// A stored link's home, `from` and `to` — the home from the link's own
/// address.
fn read_link(board: &Board, link: &Address) -> Result<Option<(Address, Address, Vec<Address>)>, MirrorError> {
    let v = board.op_ok(&json!({ "op": "read_link", "a": link.to_string() }))?;
    if v["link"].is_null() {
        return Ok(None);
    }
    let slot = |i: usize| -> Vec<Address> {
        v["link"]["slots"][i]
            .as_array()
            .map(|spans| spans.iter().filter_map(|s| s["start"].as_str().and_then(parse_address)).collect())
            .unwrap_or_default()
    };
    let Some(home) = skep_address::document_of(link) else { return Ok(None) };
    let from = slot(0);
    let Some(atom) = from.first().cloned() else { return Ok(None) };
    Ok(Some((home, atom, slot(1))))
}

/// An atom at the head of its home: the append-only guess, else the head's
/// whole image.
fn atom_at_head(board: &Board, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
    let retrieve = |pos: u64| -> Result<Option<String>, MirrorError> {
        let v = board.op(&json!({ "op": "retrieve_v", "specs": [{ "doc": home.to_string(), "span": { "start": format!("1.{pos}"), "width": "0.1" } }] }))?;
        Ok(v["items"].as_array().filter(|i| i.len() == 1).and_then(|i| i[0]["atom"].as_str()).map(str::to_string))
    };
    let image = |from: u64, width: u64| -> Result<Vec<(Address, u64)>, MirrorError> {
        let v = board.op(&json!({ "op": "image", "d": home.to_string(), "region": [{ "start": format!("1.{from}"), "width": format!("0.{width}") }] }))?;
        Ok(v["runs"]
            .as_array()
            .map(|runs| {
                runs.iter()
                    .filter_map(|r| Some((parse_address(r["i_start"].as_str()?)?, r["width"].as_str()?.parse::<u64>().ok()?)))
                    .collect()
            })
            .unwrap_or_default())
    };
    if let Some(n) = addr.element_field().filter(|e| e.len() == 2).and_then(|e| u64::try_from(&e[1]).ok()) {
        let runs = image(n, 1)?;
        if runs.len() == 1 && runs[0].0 == *addr {
            return retrieve(n);
        }
    }
    let v = board.op(&json!({ "op": "retrieve_doc_v_span_set", "doc": home.to_string() }))?;
    let extent = v["set"]
        .as_array()
        .and_then(|set| set.iter().find(|s| s["start"].as_str() == Some("1.1")))
        .and_then(|s| s["width"].as_str()?.strip_prefix("0.")?.parse::<u64>().ok())
        .unwrap_or(0);
    if extent == 0 {
        return Ok(None);
    }
    let mut pos = 1u64;
    for (start, width) in image(1, extent)? {
        let s: Vec<_> = start.tumbler().iter().cloned().collect();
        let a: Vec<_> = addr.tumbler().iter().cloned().collect();
        if s.len() == a.len() && s[..s.len() - 1] == a[..a.len() - 1] {
            if let (Ok(sl), Ok(al)) = (u64::try_from(&s[s.len() - 1]), u64::try_from(&a[a.len() - 1])) {
                if al >= sl && al - sl < width {
                    return retrieve(pos + (al - sl));
                }
            }
        }
        pos += width;
    }
    Ok(None)
}

/// The account's live `key_set`.
fn live_keys(board: &Board, account: &Address) -> Result<Vec<Enrolled>, MirrorError> {
    let v = board.op(&json!({ "op": "key_set", "account": account.to_string() }))?;
    Ok(v["enrolled"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let key = PublicKey::parse(e["alg"].as_str()?, e["key"].as_str()?).ok()?;
                    Some(Enrolled { key, anchor: e["anchor"].as_bool().unwrap_or(false) })
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Whether a retraction link targets `link`.
fn retracted(board: &Board, link: &Address, retraction: &Address) -> Result<bool, MirrorError> {
    let v = board.op_ok(&json!({ "op": "find_links_ftt", "q": {
        "home": "any", "from": "any", "to": [unit_span_json(link)], "ty": [unit_span_json(retraction)],
    }}))?;
    Ok(v["addrs"].as_array().is_some_and(|a| !a.is_empty()))
}

fn unit_span_json(a: &Address) -> Value {
    let span = skep_identity::unit_span(a);
    json!({ "start": span.start().to_string(), "width": span.width().to_string() })
}
