//! THE GUEST-READING RESOLVE (REG-3.24, REG-3.33): a reader holding no
//! mirror answers a prefix by SCANNING — every CANDIDATE BINDING of the
//! board, REG-3.24's word: every binding-typed link, by its class — each
//! link read, each atom fetched — inside the design and outside the
//! availability claim, exactly as available as the root. It holds no
//! positions, so no record it reads can be judged as of one: its verdicts
//! are UNDETERMINABLE HERE. Built here to be PRICED ([`GuestCost`]), never
//! to be the hot-loop reader. A child of `walk`: its answer renders through
//! the walk's own faces ([`face_of`]).
//!
//! It folds what it reads into a [`Ledger`] — the rules alone — and never
//! into an [`Index`](crate::index::Index), whose one writer is the mirror's
//! gate: every candidate binding the class scan lists, FROM EVERY HOME — the
//! binding home's bindings and the records REG-2.6 calls no binding alike —
//! each UNDETERMINABLE HERE. Neither the verdict nor the registrar's home
//! (REG-2.8) admits what this resolve answers from.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{doc_1_of, Enrolled};
use skep_registry::{parse, t_binding, t_endpoint, Body, BodyKind};

use super::face_of;
use crate::board::{
    content_extent, content_ordinal_in, image_frame, position_in, retrieve_frame, runs_of, span_set_frame,
    unit_span_json, Board,
};
use crate::index::Ledger;
use crate::mirror::MirrorError;
use crate::origin::{NameResolver, Transports};
use crate::parse_address;
use crate::state::{BindingRecord, EndpointRecord, Judged, Resolution, Verdict};

/// What the guest-reading resolve cost (the investigation §3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuestCost {
    /// Candidate bindings the class scan listed: binding-typed links from
    /// every home (REG-3.24).
    pub candidate_bindings_scanned: u64,
    /// Atoms read.
    pub atoms_read: u64,
    /// Wire reads made, every kind.
    pub reads: u64,
    /// Wall time.
    pub time: Duration,
}

/// THE GUEST-READING RESOLVE of `prefix` with NO mirror (REG-3.24, REG-3.33):
/// every candidate binding of the board — every binding-typed link, by its
/// class (`window_ftt` over the binding's type, paged) — each read, each
/// atom fetched by its head position and parsed; the prefix's candidate
/// bindings in their home's link order (journal order within one home); the
/// account's live key set; its endpoint deposits by the same scan over its
/// doc 1; the retraction of each by its own retraction link. Every verdict
/// UNDETERMINABLE HERE: no position is held to judge a record as of. Answers
/// the face and the cost.
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
    // Every candidate binding on the board: every binding-typed link, by its
    // class.
    let mut links = scan_class(board, t_binding(), None)?;
    cost.candidate_bindings_scanned = links.len() as u64;
    links.sort_unstable();
    for link in &links {
        let Some((home, from, to)) = read_link(board, link)? else { continue };
        let Some(text) = atom_at_head(board, &home, &from)? else { continue };
        cost.atoms_read += 1;
        let Ok(record) = parse(BodyKind::Binding, text.as_bytes()) else { continue };
        let Body::Binding(b) = record.body else { continue };
        let Some(prefix) = parse_address(&b.prefix) else { continue };
        ledger.fold_binding(Judged {
            position: 0,
            link: link.clone(),
            home,
            record: BindingRecord {
                prefix,
                account: to.first().cloned(),
                replaces: b.replaces.as_deref().and_then(parse_address),
                honored: false,
            },
            verdict: Verdict::UndeterminableHere,
        });
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
    deposits.sort_unstable();
    for link in &deposits {
        let Some((dep_home, from, _)) = read_link(board, link)? else { continue };
        if dep_home != home {
            continue;
        }
        let Some(text) = atom_at_head(board, &dep_home, &from)? else { continue };
        cost.atoms_read += 1;
        let Ok(record) = parse(BodyKind::Endpoint, text.as_bytes()) else { continue };
        let Body::Endpoint(e) = record.body else { continue };
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
/// whole image — an image whose runs do not all read locating nothing.
fn atom_at_head(board: &Board, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
    let retrieve = |pos: u64| -> Result<Option<String>, MirrorError> {
        let v = board.op(&retrieve_frame(home, pos))?;
        Ok(v["items"].as_array().filter(|i| i.len() == 1).and_then(|i| i[0]["atom"].as_str()).map(str::to_string))
    };
    let image = |from: u64, width: u64| -> Result<Vec<(Address, u64)>, MirrorError> {
        Ok(runs_of(&board.op(&image_frame(home, from, width))?).unwrap_or_default())
    };
    if let Some(n) = content_ordinal_in(home, addr) {
        let runs = image(n, 1)?;
        if runs.len() == 1 && runs[0].0 == *addr {
            return retrieve(n);
        }
    }
    let extent = content_extent(&board.op(&span_set_frame(home))?).unwrap_or(0);
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;

    use skep_registry::{encode, Binding, Endpoint};
    use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

    use super::*;
    use crate::http::{Method, Transport, TransportError};

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// A span over one address as `read_link` answers a slot.
    fn span(start: &str) -> Value {
        json!({ "start": start, "width": "0.1" })
    }

    /// A BOARD THE SUITE HOLDS FIXED, as the guest reads it over `/op` alone:
    /// one candidate binding, the registrar's, binding `1.2` to `1.0.2`; that
    /// account's one endpoint deposit in its doc 1, retracted by nothing; its
    /// live table one key; every atom at its home's head, at the content
    /// ordinal it was minted at. Any other read is no read this board answers.
    struct Guest;

    impl Transport for Guest {
        fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
            assert_eq!((method, path), (Method::Post, "/op"), "the guest reads /op alone");
            let frame: Value = serde_json::from_slice(body).expect("a frame");
            let window = |link: &str| json!({ "resp": "window", "window": { "batch": [link], "exhausted": true } });
            let doc = frame["d"].as_str().or(frame["specs"][0]["doc"].as_str());
            let answer = match (frame["op"].as_str(), frame["a"].as_str(), doc) {
                (Some("window_ftt"), _, _) if frame["q"]["ty"][0] == unit_span_json(t_binding()) => window("1.0.1.0.1.0.2.1"),
                (Some("window_ftt"), _, _) if frame["q"]["ty"][0] == unit_span_json(t_endpoint()) => {
                    assert_eq!(frame["q"]["home"], json!([unit_span_json(&a("1.0.2.0.1"))]), "the scan over the account's doc 1");
                    window("1.0.2.0.1.0.2.1")
                }
                (Some("read_link"), Some("1.0.1.0.1.0.2.1"), _) => json!({ "resp": "link", "link": { "slots": [
                    [span("1.0.1.0.1.0.1.1")], [span("1.0.2")], [unit_span_json(t_binding())],
                ] } }),
                (Some("read_link"), Some("1.0.2.0.1.0.2.1"), _) => json!({ "resp": "link", "link": { "slots": [
                    [span("1.0.2.0.1.0.1.1")], [], [unit_span_json(t_endpoint())],
                ] } }),
                (Some("image"), _, Some(home)) => json!({ "resp": "runs", "runs": [{ "i_start": format!("{home}.0.1.1"), "width": "1" }] }),
                (Some("retrieve_v"), _, Some("1.0.1.0.1")) => {
                    let binding = encode(&Body::Binding(Binding { prefix: "1.2".into(), replaces: None }), None);
                    json!({ "resp": "delivery", "items": [{ "atom": binding }] })
                }
                (Some("retrieve_v"), _, Some("1.0.2.0.1")) => {
                    let origins = vec!["https://acme.example".to_string()];
                    let endpoint = encode(&Body::Endpoint(Endpoint { origins, replaces: None }), None);
                    json!({ "resp": "delivery", "items": [{ "atom": endpoint }] })
                }
                (Some("key_set"), _, _) if frame["account"] == "1.0.2" => {
                    let key = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[2; 32]).expect("tag 1").public_key().clone();
                    json!({ "resp": "key_set", "as_of": 9, "enrolled": [{ "alg": key.alg(), "key": key.to_hex(), "anchor": true }] })
                }
                (Some("find_links_ftt"), _, _) => json!({ "resp": "links", "addrs": [] }),
                _ => panic!("a read this board does not answer: {frame}"),
            };
            Ok((200, answer.to_string().into_bytes()))
        }
    }

    /// This resolver's own resolution of a name, fixed: `acme.example` at a
    /// public address.
    struct Names;

    impl NameResolver for Names {
        fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }
    }

    /// THE GUEST-READING RESOLVE JUDGES NO RECORD (REG-3.24, REG-3.33): it
    /// holds no position to judge one as of, so the verdict beside every
    /// record it answers from — the binding's and the endpoint's alike — is
    /// UNDETERMINABLE HERE, never one manufactured from the input it lacks;
    /// and a prefix no candidate binding names is UNREGISTERED.
    #[test]
    fn the_guest_reading_resolve_judges_every_record_undeterminable_here() {
        let board = Board::new(Box::new(Guest));
        let (face, cost) = guest_resolve(&board, &a("1.2"), &Names, &Transports::default()).expect("the guest resolve");
        match face {
            Resolution::Bound { standing, keys, endpoint, dial, .. } => {
                assert_eq!(standing.current.link, a("1.0.1.0.1.0.2.1"));
                assert!(standing.history.iter().all(|b| b.verdict == Verdict::UndeterminableHere), "{:?}", standing.history);
                assert_eq!(endpoint.verdict, Verdict::UndeterminableHere);
                assert_eq!(keys.map(|k| k.len()), Some(1), "the live table");
                assert_eq!(dial.origin.as_str(), "https://acme.example");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!((cost.candidate_bindings_scanned, cost.atoms_read), (1, 2));
        let (face, _) = guest_resolve(&board, &a("1.3"), &Names, &Transports::default()).expect("the guest resolve");
        assert_eq!(face, Resolution::Unregistered { prefix: a("1.3") });
    }
}
