use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::rc::Rc;

use serde_json::{json, Value};
use skep_registry::{encode, Binding, Endpoint, Origins};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::*;
use crate::board::unit_span_json;
use crate::http::{Method, Transport, TransportError};
use crate::parse_address;

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

/// The claimant every claimed board below names.
const CLAIMANT: &str = "1.0.1";

/// The claimant's doc 1: the binding home.
const REGISTRY: &str = "1.0.1.0.1";

/// The account `1.2` is bound to.
const ORG: &str = "1.0.2";

/// The bound account's doc 1.
const ORG_DOC1: &str = "1.0.2.0.1";

/// A span over one address as `read_link` answers a slot.
fn span(start: &str) -> Value {
    json!({ "start": start, "width": "0.1" })
}

/// Returns a slot as `read_link` answers it: one span over each of `addrs`.
fn slot(addrs: &[&str]) -> Value {
    Value::Array(addrs.iter().map(|s| span(s)).collect())
}

/// Returns the claim's type, the commons' `3.3`.
fn t_claim() -> Address {
    commons_type(&[3])
}

/// Returns a sig-less binding of `prefix` as its atom carries it.
///
/// The guest judges no `sig`.
fn binding_text(prefix: &str) -> String {
    encode(&Body::Binding(Binding { prefix: a(prefix), replaces: None }), None)
}

/// Returns a sig-less endpoint of `origin` as its atom carries it.
fn endpoint_text(origin: &str) -> String {
    let origins = Origins::new(vec![origin.to_string()]).expect("one origin");
    encode(&Body::Endpoint(Endpoint { origins, replaces: None }), None)
}

/// A board the suite holds fixed, as the guest reads it over `/op` alone.
///
/// It serves the links each class scan lists, by type and whatever home the
/// scan names; each stored link's slots as `read_link` serves them; each
/// atom at its home's head, at the content ordinal it was minted at; every
/// account's live table, one key; and, on the active view, every link that
/// names the atom asked. Every frame asked is kept, in order; any other read
/// is no read this board answers.
#[derive(Default)]
struct Fixed {
    listed: Vec<(Address, String)>,
    links: BTreeMap<String, Value>,
    atoms: BTreeMap<String, String>,
    asked: RefCell<Vec<Value>>,
}

impl Fixed {
    /// Returns the board with a link at `link`, listed by `listed_as`'s scan.
    ///
    /// The link's slots are `from`, `to` and `ty`, as `read_link` serves
    /// them.
    fn link(mut self, listed_as: &Address, link: &str, from: Value, to: Value, ty: Value) -> Fixed {
        self.listed.push((listed_as.clone(), link.to_string()));
        self.links.insert(link.to_string(), json!([from, to, ty]));
        self
    }

    /// Returns the board with a claim at `link` (AUTH-2.48).
    ///
    /// Its `from` is the claimant, its `to` empty, its type the claim's.
    fn claim(self, link: &str, claimant: &str) -> Fixed {
        self.link(&t_claim(), link, slot(&[claimant]), slot(&[]), json!([unit_span_json(&t_claim())]))
    }

    /// Returns the board with a record deposit linked at `link`.
    ///
    /// The record is `text`, the atom at `atom`; the link is typed `ty` and
    /// names `to`.
    fn deposit(mut self, ty: &Address, link: &str, atom: &str, to: &[&str], text: &str) -> Fixed {
        self.atoms.insert(atom.to_string(), text.to_string());
        self.link(ty, link, slot(&[atom]), slot(to), json!([unit_span_json(ty)]))
    }

    /// Returns the query of every class scan asked of `ty`, in order.
    fn scans_of(&self, ty: &Address) -> Vec<Value> {
        let ty = json!([unit_span_json(ty)]);
        self.asked.borrow().iter().filter(|f| f["op"] == "window_ftt" && f["q"]["ty"] == ty).map(|f| f["q"].clone()).collect()
    }

    /// Returns every link `read_link` was asked for, in order.
    fn links_read(&self) -> Vec<String> {
        self.asked.borrow().iter().filter(|f| f["op"] == "read_link").filter_map(|f| f["a"].as_str().map(str::to_string)).collect()
    }

    fn served(&self, frame: &Value) -> Value {
        match frame["op"].as_str().unwrap_or("") {
            "window_ftt" => {
                let ty = &frame["q"]["ty"];
                let batch: Vec<&str> =
                    self.listed.iter().filter(|(t, _)| *ty == json!([unit_span_json(t)])).map(|(_, link)| link.as_str()).collect();
                json!({ "resp": "window", "window": { "batch": batch, "exhausted": true } })
            }
            "read_link" => match self.links.get(frame["a"].as_str().expect("a link")) {
                Some(slots) => json!({ "resp": "link", "link": { "slots": slots } }),
                None => json!({ "resp": "link", "link": null }),
            },
            "image" => {
                let doc = frame["d"].as_str().expect("a doc");
                let (from, width) = (count(&frame["region"][0]["start"], "1."), count(&frame["region"][0]["width"], "0."));
                let runs: Vec<Value> = (from..from + width)
                    .map(|n| format!("{doc}.0.1.{n}"))
                    .filter(|atom| self.atoms.contains_key(atom))
                    .map(|atom| json!({ "i_start": atom, "width": "1" }))
                    .collect();
                json!({ "resp": "runs", "runs": runs })
            }
            "retrieve_v" => {
                let spec = &frame["specs"][0];
                let atom = format!("{}.0.1.{}", spec["doc"].as_str().expect("a doc"), count(&spec["span"]["start"], "1."));
                match self.atoms.get(&atom) {
                    Some(text) => json!({ "resp": "delivery", "items": [{ "atom": text }] }),
                    None => json!({ "resp": "rejected", "op": "retrieve_v", "code": "out_of_range" }),
                }
            }
            "key_set" => {
                let key = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[2; 32]).expect("tag 1").public_key().clone();
                json!({ "resp": "key_set", "as_of": 9, "enrolled": [{ "alg": key.alg(), "key": key.to_hex(), "anchor": true }] })
            }
            "find_links_ftt" => {
                let atom = &frame["q"]["from"][0]["start"];
                let addrs: Vec<&String> = self.links.iter().filter(|(_, slots)| &slots[0][0]["start"] == atom).map(|(link, _)| link).collect();
                json!({ "resp": "addrs", "addrs": addrs })
            }
            _ => panic!("a read this board does not answer: {frame}"),
        }
    }
}

/// Returns the count a wire tumbler `prefix.n` spells: its `n`.
fn count(text: &Value, prefix: &str) -> u64 {
    text.as_str().and_then(|s| s.strip_prefix(prefix)).and_then(|n| n.parse().ok()).expect("a count")
}

impl Transport for Fixed {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        assert_eq!((method, path), (Method::Post, "/op"), "the guest reads /op alone");
        let frame: Value = serde_json::from_slice(body).expect("a frame");
        self.asked.borrow_mut().push(frame.clone());
        Ok((200, self.served(&frame).to_string().into_bytes()))
    }
}

/// Returns the registry most cells stand on.
///
/// `1.0.1`'s claim stands in its doc 1 with its one binding there, `1.2` to
/// `1.0.2`; that account's one endpoint deposit stands in its own doc 1.
fn registry() -> Fixed {
    Fixed::default()
        .claim("1.0.1.0.1.0.2.1", CLAIMANT)
        .deposit(t_binding(), "1.0.1.0.1.0.2.2", "1.0.1.0.1.0.1.1", &[ORG], &binding_text("1.2"))
        .deposit(t_endpoint(), "1.0.2.0.1.0.2.1", "1.0.2.0.1.0.1.1", &[], &endpoint_text("https://acme.example"))
}

/// Returns the guest's resolve of `prefix` over `board`.
fn guest(board: &Rc<Fixed>, prefix: &str) -> Result<(Resolution, GuestCost), BoardError> {
    guest_resolve(&Board::new(Box::new(board.clone())), &a(prefix), &Names, &Transports::default())
}

/// Returns a home slot naming `doc` alone, as a class scan's query spells it.
fn home(doc: &str) -> Value {
    json!([unit_span_json(&a(doc))])
}

/// A BOARD WHOSE CLASS SCAN ANSWERS `windows` in turn, each a batch, a
/// `next` and `exhausted`: every request recorded, and a request past
/// the last window a panic — so a scan that would page forever fails.
struct Windows {
    windows: Vec<(Vec<String>, Option<String>, bool)>,
    asked: Cell<usize>,
}

impl Transport for Windows {
    fn exchange(&self, _: Method, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let (batch, next, exhausted) = self.windows.get(self.asked.get()).expect("a window this board serves").clone();
        self.asked.set(self.asked.get() + 1);
        let answer = json!({ "resp": "page", "window": { "batch": batch, "next": next, "exhausted": exhausted } });
        Ok((200, answer.to_string().into_bytes()))
    }
}

/// A WINDOW THAT DOES NOT ADVANCE IS REFUSED (skep-discovery's `Window`):
/// a scan pages through full windows, ascending, each past the cursor and
/// naming its last as `next`, to the exhausted one; a window that is not
/// the last and is short, re-serves the cursor, or names another `next`
/// is refused at once, never asked again.
#[test]
fn a_window_that_does_not_advance_is_refused() {
    let n = WINDOW.get();
    let links = |from: usize| (from..from + n).map(|k| format!("1.0.1.0.1.0.2.{k}")).collect::<Vec<_>>();
    let scan = |windows: Vec<(Vec<String>, Option<String>, bool)>| {
        let board = Rc::new(Windows { windows, asked: Cell::new(0) });
        let scanned = scan_class(&Board::new(Box::new(board.clone())), t_binding(), None);
        (scanned, board.asked.get())
    };
    let (first, second) = (links(1), links(1 + n));
    let last_of = |batch: &[String]| batch.last().cloned();
    let (scanned, asked) = scan(vec![(first.clone(), last_of(&first), false), (vec!["1.0.1.0.1.0.2.999".into()], None, true)]);
    assert_eq!((scanned.map(|links| links.len()), asked), (Ok(n + 1), 2), "a full window, then the last");
    for (window, case) in [
        ((Vec::new(), None, false), "an empty window that is not the last"),
        ((first[..n - 1].to_vec(), last_of(&first[..n - 1]), false), "a short window"),
        ((first.clone(), Some(first[0].clone()), false), "a next that is not its last"),
    ] {
        let (scanned, asked) = scan(vec![window]);
        assert!(matches!(scanned, Err(BoardError::Malformed(_))), "{case}");
        assert_eq!(asked, 1, "{case}: never asked again");
    }
    let replayed = vec![(second.clone(), last_of(&second), false), (first.clone(), last_of(&first), false)];
    let (scanned, asked) = scan(replayed);
    assert!(matches!(scanned, Err(BoardError::Malformed(_))), "a window behind its cursor");
    assert_eq!(asked, 2);
}

/// This resolver's own resolution of a name, fixed: `acme.example` at a
/// public address.
struct Names;

impl NameResolver for Names {
    fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        Ok(vec!["93.184.216.34".parse().unwrap()])
    }
}

/// Checks that the guest judges no record and scans the binding home alone.
///
/// It holds no position to judge a record as of (REG-3.24, REG-3.33), so
/// the verdict beside every record it answers from — the binding's and the
/// endpoint's alike — is `UndeterminableHere`, never one manufactured from
/// the input it lacks; and a prefix no candidate binding names is
/// unregistered. Its scans are the binding home's (REG-2.5): the claim's
/// class over every home first, then the binding's over the claimant's
/// doc 1 alone, the endpoint's over the bound account's, and the deposit
/// asked of the board's active view.
#[test]
fn the_guest_reading_resolve_judges_every_record_undeterminable_here() {
    let board = Rc::new(registry());
    let (face, cost) = guest(&board, "1.2").expect("the guest resolve");
    match face {
        Resolution::Bound { standing, keys, endpoint, dial, .. } => {
            assert_eq!(standing.current.link, a("1.0.1.0.1.0.2.2"));
            assert!(standing.history.iter().all(|b| b.verdict == Verdict::UndeterminableHere), "{:?}", standing.history);
            assert_eq!(endpoint.verdict, Verdict::UndeterminableHere);
            assert_eq!(keys.map(|k| k.len()), Some(1), "the live table");
            assert_eq!(dial.origin.as_str(), "https://acme.example");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!((cost.candidate_bindings_scanned, cost.atoms_read), (1, 2));
    let claims = json!({ "home": "any", "from": "any", "to": "any", "ty": [unit_span_json(&t_claim())] });
    assert_eq!(board.scans_of(&t_claim()), [claims], "the claim's class, over every home");
    let bindings: Vec<Value> = board.scans_of(t_binding()).iter().map(|q| q["home"].clone()).collect();
    assert_eq!(bindings, [home(REGISTRY)], "the binding's class, over the binding home alone");
    let endpoints: Vec<Value> = board.scans_of(t_endpoint()).iter().map(|q| q["home"].clone()).collect();
    assert_eq!(endpoints, [home(ORG_DOC1)], "the endpoint's class, over the bound account's doc 1");
    let active = board.asked.borrow().iter().find(|f| f["op"] == "find_links_ftt").map(|f| f["q"].clone());
    let deposit = json!({
        "home": home(ORG_DOC1), "from": [unit_span_json(&a("1.0.2.0.1.0.1.1"))],
        "to": "any", "ty": [unit_span_json(t_endpoint())],
    });
    assert_eq!(active, Some(deposit), "the deposit asked of the board's active view");
    let (face, _) = guest(&board, "1.3").expect("the guest resolve");
    assert_eq!(face, Resolution::Unregistered { prefix: a("1.3") });
}

/// Checks that a board holding no claim binds no prefix (REG-2.5).
///
/// With no claim there is no binding home, so a binding-typed link the board
/// serves — here in the doc 1 a claimant's would be — is never scanned for
/// and never read, and the prefix it names is unregistered after the claim's
/// class scan alone.
#[test]
fn a_board_holding_no_claim_binds_no_prefix() {
    let board = Rc::new(Fixed::default().deposit(t_binding(), "1.0.1.0.1.0.2.2", "1.0.1.0.1.0.1.1", &[ORG], &binding_text("1.2")));
    let (face, cost) = guest(&board, "1.2").expect("the guest resolve");
    assert_eq!(face, Resolution::Unregistered { prefix: a("1.2") });
    assert_eq!((cost.candidate_bindings_scanned, cost.atoms_read, cost.reads), (0, 0, 1), "the claim's class scan alone");
    assert!(board.scans_of(t_binding()).is_empty(), "no binding scanned for");
}

/// Checks that a board serving two claims is refused (AUTH-2.67, AUTH-2.68).
///
/// A board admits one claim, and this reader holds no positions to tell
/// which came first, so two claim-shaped links, each in its claimant's
/// doc 1, are refused, and no binding home is guessed between them.
#[test]
fn a_board_serving_two_claims_is_refused() {
    let board = Rc::new(registry().claim("1.0.2.0.1.0.2.2", ORG));
    let refused = guest(&board, "1.2").map(|(face, _)| face);
    assert!(matches!(refused, Err(BoardError::Malformed(_))), "{refused:?}");
    assert!(board.scans_of(t_binding()).is_empty(), "no binding scanned for");
}

/// Checks that a claim-typed link of another shape names no binding home.
///
/// The shape is the claim's (AUTH-2.48; AUTH-2.67's first two conditions).
/// Listed by the claim's class scan beside the board's one claim are a link
/// homed outside its account's doc 1, one whose `from` names another
/// account, one whose `from` names a second account beside its own, one
/// with a `to`, one typed a subtype of the claim's type, and one typed the
/// claim's type beside another. Each is read and set aside: taken for a
/// claim, any of them would be a second and the board refused. The one
/// claim names the binding home, and the claimant's binding answers.
#[test]
fn a_claim_typed_link_of_another_shape_names_no_binding_home() {
    let claim = json!([unit_span_json(&t_claim())]);
    let shapes = [
        ("1.0.3.0.3.0.2.1", slot(&["1.0.3"]), slot(&[]), claim.clone()),
        ("1.0.4.0.1.0.2.1", slot(&["1.0.5"]), slot(&[]), claim.clone()),
        ("1.0.6.0.1.0.2.1", slot(&["1.0.6", "1.0.7"]), slot(&[]), claim.clone()),
        ("1.0.8.0.1.0.2.1", slot(&["1.0.8"]), slot(&[CLAIMANT]), claim.clone()),
        ("1.0.9.0.1.0.2.1", slot(&["1.0.9"]), slot(&[]), json!([unit_span_json(&commons_type(&[3, 1]))])),
        ("1.0.10.0.1.0.2.1", slot(&["1.0.10"]), slot(&[]), json!([unit_span_json(&t_claim()), unit_span_json(t_binding())])),
    ];
    let mut fixed = registry();
    for (link, from, to, ty) in shapes.clone() {
        fixed = fixed.link(&t_claim(), link, from, to, ty);
    }
    let board = Rc::new(fixed);
    let (face, _) = guest(&board, "1.2").expect("one claim, every other shape set aside");
    match face {
        Resolution::Bound { standing, .. } => assert_eq!(standing.current.home, a(REGISTRY)),
        other => panic!("{other:?}"),
    }
    let read = board.links_read();
    assert!(shapes.iter().all(|(link, ..)| read.iter().any(|r| r == link)), "each read: {read:?}");
    let bindings: Vec<Value> = board.scans_of(t_binding()).iter().map(|q| q["home"].clone()).collect();
    assert_eq!(bindings, [home(REGISTRY)], "the claimant's doc 1 the binding home");
}

/// Checks that a binding listed from another home is no candidate (REG-2.6).
///
/// A binding the class scan lists from the bound account's own doc 1 —
/// served past the home the scan named — is neither counted nor read, and
/// the prefix it names is unregistered; the binding home's own binding
/// still answers.
#[test]
fn a_binding_listed_from_another_home_is_no_candidate() {
    let board = Rc::new(registry().deposit(t_binding(), "1.0.2.0.1.0.2.2", "1.0.2.0.1.0.1.2", &[ORG], &binding_text("1.4")));
    let (face, cost) = guest(&board, "1.4").expect("the guest resolve");
    assert_eq!(face, Resolution::Unregistered { prefix: a("1.4") });
    assert_eq!(cost.candidate_bindings_scanned, 1, "the binding home's one binding");
    assert!(!board.links_read().iter().any(|l| l == "1.0.2.0.1.0.2.2"), "never read");
    let (face, _) = guest(&board, "1.2").expect("the guest resolve");
    assert!(matches!(face, Resolution::Bound { .. }), "{face:?}");
}

/// A board whose home arranges 5,000 atoms in as many runs, the atom at
/// V-ordinal 4,500 the record asked for: the home's image is answered as the
/// wire pages it, and `retrieve_v` answers that one position alone. Every
/// `image` frame's first ordinal is kept.
struct LongHome {
    images: Rc<RefCell<Vec<u64>>>,
}

impl Transport for LongHome {
    fn exchange(&self, _: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        assert_eq!(path, "/op", "the guest reads the head alone");
        let frame: Value = serde_json::from_slice(body).expect("a frame");
        let answer = match frame["op"].as_str() {
            Some("retrieve_doc_v_span_set") => json!({ "resp": "span_set", "set": [{ "start": "1.1", "width": "0.5000" }] }),
            Some("image") => {
                let start = frame["region"][0]["start"].as_str().and_then(|s| s.strip_prefix("1.")).and_then(|n| n.parse().ok()).expect("a start");
                self.images.borrow_mut().push(start);
                crate::board::paged_image_of(&frame, 5_000, 9)
            }
            Some("retrieve_v") if frame["specs"][0]["span"]["start"] == "1.4500" => json!({ "resp": "delivery", "items": [{ "atom": "the record" }] }),
            _ => panic!("a read this board does not answer: {frame}"),
        };
        Ok((200, answer.to_string().into_bytes()))
    }
}

/// **The head's whole image** of a home in more runs than one answer carries:
/// the append-only guess misses, the image is read whole — two frames, the
/// second from the first's go-on — and the atom is read at its own V-ordinal,
/// on the second page (the mutant that takes the first page for the image
/// locates nothing, and the record reads as absent).
#[test]
fn an_atom_on_the_second_page_of_its_homes_image_is_found_at_the_head() {
    let images = Rc::new(RefCell::new(Vec::new()));
    let board = Board::new(Box::new(LongHome { images: images.clone() }));
    let (home, atom) = (a(ORG_DOC1), a(&format!("{ORG_DOC1}.0.1.9000")));
    assert_eq!(atom_at_head(&board, &home, &atom), Ok(Some("the record".to_string())));
    assert_eq!(*images.borrow(), [9_000, 1, 4_097], "the guess at the atom's own ordinal, then the whole image in two frames");
}
