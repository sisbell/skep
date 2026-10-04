//! THE GUEST-READING RESOLVE (REG-3.24, REG-3.33): a reader holding no
//! mirror answers a prefix by SCANNING — every binding link of the board by
//! its class, each link read, each atom fetched — inside the design and
//! outside the availability claim, exactly as available as the root. It
//! holds no positions, so no record it reads can be judged as of one: its
//! verdicts are UNDETERMINABLE HERE. Built here to be PRICED
//! ([`GuestCost`]), never to be the hot-loop reader. A child of `walk`: its
//! answer renders through the walk's own faces ([`face_of`]).
//!
//! It folds what it reads into a [`Ledger`] — the rules alone — and never
//! into an [`Index`](crate::index::Index), whose one writer is the mirror's
//! gate: every binding the class scan lists, FROM EVERY HOME, each
//! UNDETERMINABLE HERE. Neither the verdict nor the registrar's home
//! (REG-2.8) admits what this resolve answers from.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{doc_1_of, Enrolled};
use skep_registry::{parse, t_binding, t_endpoint, Body, BodyKind};

use super::face_of;
use crate::board::{content_extent, position_in, unit_span_json, Board};
use crate::index::Ledger;
use crate::mirror::MirrorError;
use crate::origin::{NameResolver, Transports};
use crate::parse_address;
use crate::state::{BindingRecord, EndpointRecord, Judged, Resolution, Verdict};

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
    let mut ledger = Ledger::default();
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
                            ledger.fold_binding(Judged {
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
    let Some(standing) = ledger.standing(prefix) else {
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
    for link in &deposits {
        if let Some((dep_home, from, _)) = read_link(board, link)? {
            if dep_home != home {
                continue;
            }
            if let Some(text) = atom_at_head(board, &dep_home, &from)? {
                cost.atoms_read += 1;
                if let Ok(record) = parse(BodyKind::Endpoint, text.as_bytes()) {
                    if let Body::Endpoint(e) = record.body {
                        let honored = ledger.fold_endpoint(Judged {
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
                        if honored && board.retraction_stands(link)? {
                            ledger.nullify(link);
                        }
                    }
                }
            }
        }
    }
    let endpoint = ledger.current_endpoint(&home).cloned();
    let any = ledger.any_honored_endpoint(&home);
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
    let Some([from, to, _]) = board.link_slots(link)? else { return Ok(None) };
    let Some(home) = skep_address::document_of(link) else { return Ok(None) };
    let Some(atom) = from.first().cloned() else { return Ok(None) };
    Ok(Some((home, atom, to)))
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
    let extent = content_extent(&v).unwrap_or(0);
    if extent == 0 {
        return Ok(None);
    }
    match position_in(&image(1, extent)?, addr) {
        Some(pos) => retrieve(pos),
        None => Ok(None),
    }
}

/// The account's live key set ([`Board::key_set`]); `None` where the answer
/// is no key set — this reader could not read it.
fn live_keys(board: &Board, account: &Address) -> Result<Option<Vec<Enrolled>>, MirrorError> {
    Ok(board.key_set(account)?.map(|answer| answer.enrolled))
}
