use std::cell::RefCell;
use std::rc::Rc;

use skep_registry::{t_binding, t_endpoint};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::*;

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

/// A board that answers every exchange with one status and one body.
struct Canned(u16, String);

impl Transport for Canned {
    fn exchange(&self, _: Method, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        Ok((self.0, self.1.clone().into_bytes()))
    }
}

fn canned(body: Value) -> Board {
    Board::new(Box::new(Canned(200, body.to_string())))
}

/// A board that answers every read with a well-formed empty answer of
/// its kind, `/op-at` only after `busy` refusals `history_busy`.
struct Busy {
    busy: Cell<u32>,
}

impl Transport for Busy {
    fn exchange(&self, method: Method, path: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let answer = match (method, path) {
            (Method::Post, "/op-at") if self.busy.get() > 0 => {
                self.busy.set(self.busy.get() - 1);
                return Ok((503, json!({ "error": "history_busy" }).to_string().into_bytes()));
            }
            (Method::Post, "/op" | "/op-at") => json!({ "resp": "runs", "runs": [] }),
            (Method::Get, "/health") => json!({}),
            (Method::Get, "/changes?since=0") => json!({ "changes": [], "last": 0, "more": false }),
            (Method::Get, "/chain?at=5") => json!({ "at": 5, "chain": "07".repeat(32) }),
            _ => panic!("a read this board does not answer: {method} {path}"),
        };
        Ok((200, answer.to_string().into_bytes()))
    }
}

/// THE COUNT OF EVERY READ: each request counted once, under its kind —
/// one over `/op-at` under its own kind AND under `op_at` — and a busy
/// answer retried counted under `busy_retries` and never again under its
/// kind; the total is the requests made, the `op_at` tally and the
/// retries never among them.
#[test]
fn every_read_is_counted_once_by_its_kind() {
    let board = Board::new(Box::new(Busy { busy: Cell::new(2) }));
    let doc = a("1.0.1.0.1");
    board.op_at(5, &image_frame(&doc, 1, 1)).expect("answered after two busy refusals");
    board.op(&span_set_frame(&doc)).expect("answered");
    board.op_at(5, &retrieve_frame(&doc, 1)).expect("answered");
    board.health().expect("answered");
    board.changes(0, None).expect("answered");
    board.chain_at(5).expect("answered");
    let r = board.reads();
    assert_eq!((r.image, r.span_set, r.retrieve, r.op_at, r.busy_retries), (1, 1, 1, 2, 2));
    assert_eq!((r.health, r.changes, r.chain), (1, 1, 1));
    assert_eq!(r.total(), 6, "{r:?}");
}

/// A chain is sixty-four hex characters, either case, and nothing else —
/// text of any other shape is no chain and never a panic: a multi-byte
/// character at sixty-four bytes, a sign `from_str_radix` would read.
#[test]
fn chain_hex_parses_at_sixty_four_characters_alone() {
    assert!(parse_chain(&"ab".repeat(32)).is_some());
    assert_eq!(parse_chain(&"AB".repeat(32)), parse_chain(&"ab".repeat(32)), "either case");
    assert!(parse_chain(&"ab".repeat(31)).is_none());
    assert!(parse_chain(&"zz".repeat(32)).is_none());
    assert!(parse_chain(&format!("a€{}", "0".repeat(60))).is_none(), "a character across a byte pair");
    assert!(parse_chain(&"+f".repeat(32)).is_none(), "a sign is no hex digit");
}

/// The values taken on the board's word are read where the wire spells
/// them: the head pair only where its chain is a chain, the board term
/// off `H.1`'s record with its chain as spelled, and a key set only where
/// the answer is one this build reads whole — its `as_of` and every entry
/// beside it; an entry of an algorithm this build holds no row for, an
/// answer with no list, and an entry with no anchor flag are no table,
/// never a smaller one and never an empty one. A board shows the reads
/// it made, and a reclaimed read names its floor where the board named
/// one.
#[test]
fn the_boards_word_is_typed_where_the_wire_spells_it() {
    let chain = "07".repeat(32);
    let board = canned(json!({ "log_position": 9, "chain_head": chain }));
    assert_eq!(board.head_pair(), Ok(Some((9, chain.clone()))));
    assert!(format!("{board:?}").contains("health: 1"), "a board shows the reads it made: {board:?}");
    assert_eq!(canned(json!({ "log_position": 9, "chain_head": "07" })).head_pair(), Ok(None), "no chain");
    assert_eq!(canned(json!({ "chain_head": chain })).head_pair(), Ok(None), "no position");
    let h1 = json!({ "position": 4, "chain": chain }).to_string();
    let term = canned(json!({ "resp": "delivery", "items": [{ "atom": h1 }] })).board_term().expect("read");
    assert_eq!(term, Some((BoardTerm { log_position: 4, chain: [7; 32] }, chain.clone())));
    assert_eq!(canned(json!({ "resp": "delivery", "items": [] })).board_term(), Ok(None), "no H.1");
    let key = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[3; 32]).expect("tag 1").public_key().clone();
    let entry = json!({ "alg": key.alg(), "key": key.to_hex(), "anchor": true });
    let answer = canned(json!({ "resp": "key_set", "as_of": 12, "enrolled": [entry] })).key_set(&a("1.0.2"));
    assert_eq!(answer, Ok(Some(KeySetAnswer { as_of: Some(12), enrolled: vec![Enrolled { key: key.clone(), anchor: true }] })));
    let refused = json!({ "resp": "rejected", "op": "key_set", "code": "no_such_account" });
    assert_eq!(canned(refused).key_set(&a("1.0.2")), Ok(None), "a refusal is no key set");
    let newer = json!({ "alg": "a-row-this-build-lacks", "key": key.to_hex(), "anchor": false });
    let partial = json!({ "resp": "key_set", "as_of": 12, "enrolled": [entry, newer] });
    assert_eq!(canned(partial).key_set(&a("1.0.2")), Ok(None), "an entry this build cannot read");
    assert_eq!(canned(json!({ "resp": "key_set", "as_of": 12 })).key_set(&a("1.0.2")), Ok(None), "no list");
    let unflagged = json!({ "alg": key.alg(), "key": key.to_hex() });
    let answer = json!({ "resp": "key_set", "as_of": 12, "enrolled": [unflagged] });
    assert_eq!(canned(answer).key_set(&a("1.0.2")), Ok(None), "an entry with no anchor flag");
    let keyless = json!({ "resp": "key_set", "as_of": 12, "enrolled": [] });
    assert_eq!(canned(keyless).key_set(&a("1.0.2")), Ok(Some(KeySetAnswer { as_of: Some(12), enrolled: Vec::new() })), "a keyless account");
    let reclaimed = |floor| BoardError::Reclaimed { floor }.to_string();
    assert_eq!(reclaimed(Some(42)), "history reclaimed below position 42");
    assert_eq!(reclaimed(None), "history reclaimed", "no floor named, none rendered");
}

/// The answers both readers of the board read alike: a link's slots, a
/// document's content extent, an image's runs — whole or not at all —
/// and an atom's V-ordinal among them, the runs taken in V-order, a gap
/// between two runs no position, and widths that overflow no position
/// either; and a content element's ordinal in its own document, never a
/// link element's nor a member's mint.
#[test]
fn the_shared_answers_read_one_way() {
    let link = json!({ "link": { "slots": [
        [{ "start": "1.0.1.0.1.0.1.4", "width": "0.1" }],
        [{ "start": "1.0.2", "width": "0.1" }, { "start": "not an address", "width": "0.1" }],
    ] } });
    assert_eq!(link_slot(&link, 0), [a("1.0.1.0.1.0.1.4")]);
    assert_eq!(link_slot(&link, 1), [a("1.0.2")], "a span that starts at no address is dropped");
    assert!(link_slot(&link, 2).is_empty(), "an absent slot is empty");
    let set = json!({ "set": [{ "start": "2.1", "width": "0.3" }, { "start": "1.1", "width": "0.7" }] });
    assert_eq!(content_extent(&set), Some(7));
    assert_eq!(content_extent(&json!({ "set": [{ "start": "2.1", "width": "0.3" }] })), None);
    let image = json!({ "resp": "runs", "runs": [
        { "i_start": "1.0.1.0.1.0.1.1", "width": "2" },
        { "i_start": "1.0.1.0.1.0.1.7", "width": "3" },
    ] });
    let runs = runs_of(&image).expect("every run reads");
    assert_eq!(runs, [(a("1.0.1.0.1.0.1.1"), 2), (a("1.0.1.0.1.0.1.7"), 3)]);
    assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.2")), Some(2));
    assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.8")), Some(4));
    assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.3")), None);
    assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.2.1")), None, "a link element");
    let overflowing = [(a("1.0.1.0.1.0.2.1"), u64::MAX), (a("1.0.1.0.1.0.1.1"), 1)];
    assert_eq!(position_in(&overflowing, &a("1.0.1.0.1.0.1.1")), None, "widths that overflow place nothing");
    let torn = json!({ "resp": "runs", "runs": [
        { "i_start": "1.0.1.0.1.0.1.1", "width": "2" },
        { "i_start": "not an address", "width": "4" },
        { "i_start": "1.0.1.0.1.0.1.7", "width": "3" },
    ] });
    assert_eq!(runs_of(&torn), None, "a run that does not read would shift every run after it");
    assert_eq!(runs_of(&json!({ "resp": "rejected" })), None);
    assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.1.4")), Some(4));
    assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.2.4")), None, "a link element");
    assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.1.0.1.4")), None, "a member's mint");
    assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.2.0.1.0.1.4")), None, "another document's element");
}

/// A LINK IS TYPED BY ITS TYPE SLOT ALONE, the daemon's own reading of a
/// registry or credential type (`single_address`): one span, the unit span
/// of a type the reader named. A span starting at that type with another
/// width, the type beside a second span, and a type the reader did not name
/// type nothing — and a link that types nothing has none of its spans
/// parsed, however many it holds.
#[test]
fn a_link_is_typed_by_its_type_slot_alone_and_read_no_further() {
    let named = [t_binding(), t_endpoint()];
    let read = |ty: Value| {
        let from: Vec<Value> = (1..=3).map(|n| json!({ "start": format!("1.0.2.0.1.0.1.{n}"), "width": "0.0.0.0.0.0.0.1" })).collect();
        let answer = json!({ "resp": "link", "link": { "slots": [from, [unit_span_json(&a("1.0.2"))], ty] } });
        canned(answer).link_slots(&a("1.0.2.0.1.0.2.1"), &named).expect("answered").expect("a link stands")
    };
    let typed = read(json!([unit_span_json(t_endpoint())]));
    assert_eq!(typed.ty.as_ref(), Some(t_endpoint()));
    assert_eq!((typed.from.len(), typed.to), (3, vec![a("1.0.2")]), "a typed link's from and to");
    let wider = json!([{ "start": t_endpoint().to_string(), "width": "0.1" }]);
    let beside = json!([unit_span_json(t_endpoint()), unit_span_json(t_binding())]);
    let unnamed = json!([unit_span_json(&skep_registry::commons_type(&[1]))]);
    for (ty, case) in [(wider, "another width"), (beside, "a second span beside it"), (unnamed, "a type not named")] {
        assert_eq!(read(ty), LinkSlots { ty: None, from: Vec::new(), to: Vec::new() }, "{case}");
    }
    let none = canned(json!({ "resp": "link", "link": null })).link_slots(&a("1.0.2.0.1.0.2.1"), &named);
    assert_eq!(none, Ok(None), "no link stands");
}

/// A board that answers every exchange with `answer`, the one frame it was
/// asked kept.
struct Asked {
    answer: Value,
    frame: RefCell<Option<Value>>,
}

impl Transport for Asked {
    fn exchange(&self, _: Method, _: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        *self.frame.borrow_mut() = Some(serde_json::from_slice(body).expect("a frame"));
        Ok((200, self.answer.to_string().into_bytes()))
    }
}

/// A DEPOSIT STANDS ON THE ACTIVE VIEW where the board's own reading answers
/// it (REG-1.11): asked as the active links homed in its home, typed its
/// type, naming its atom in their `from`, it stands where the answer lists
/// it — beside any other link — and has left the view where an answer lists
/// it nowhere; a refusal, or an answer with no list, takes nothing off the
/// view.
#[test]
fn a_deposit_stands_where_the_active_view_answers_it() {
    let (deposit, home, atom) = (a("1.0.2.0.1.0.2.1"), a("1.0.2.0.1"), a("1.0.2.0.1.0.1.1"));
    let asked = |answer: Value| {
        let board = Rc::new(Asked { answer, frame: RefCell::new(None) });
        let stands = Board::new(Box::new(board.clone())).stands_active(&deposit, &home, t_endpoint(), &atom).expect("answered");
        let frame = board.frame.borrow_mut().take().expect("asked");
        (stands, frame)
    };
    let (stands, frame) = asked(json!({ "resp": "addrs", "addrs": ["1.0.2.0.1.0.2.2", "1.0.2.0.1.0.2.1"] }));
    assert!(stands, "listed beside another link");
    let query = json!({ "op": "find_links_ftt", "q": {
        "home": [unit_span_json(&home)], "from": [unit_span_json(&atom)], "to": "any", "ty": [unit_span_json(t_endpoint())],
    }});
    assert_eq!(frame, query, "the active links of its home, its type and its atom");
    assert!(!asked(json!({ "resp": "addrs", "addrs": ["1.0.2.0.1.0.2.2"] })).0, "listed nowhere: off the view");
    assert!(!asked(json!({ "resp": "addrs", "addrs": [] })).0, "an empty list: off the view");
    let refused = json!({ "resp": "rejected", "op": "find_links_ftt", "code": "unparseable" });
    assert!(asked(refused).0, "a refusal takes nothing off the view");
    assert!(asked(json!({ "resp": "addrs" })).0, "nor does an answer with no list");
}

/// THE PAGE'S OWN RULES (wire.md §The change feed, Paging): a page is taken
/// where each entry's position rises past `since` and past the entry before
/// it, `last` is the final entry's position — `since` echoed on an empty
/// page — and an empty page announces no more; a page that re-serves a row,
/// re-orders two, names another `last`, names no position, or announces
/// more with nothing on it is refused, a seed of the page check's corpus.
#[test]
fn a_page_that_does_not_advance_is_refused() {
    let page = |since: u64, ats: &[Option<u64>], last: u64, more: bool| {
        let rows: Vec<Value> = ats.iter().map(|at| match at {
            Some(at) => json!({ "at": at, "op": "publish", "docs": [] }),
            None => json!({ "op": "publish", "docs": [] }),
        }).collect();
        canned(json!({ "changes": rows, "last": last, "more": more })).changes(since, None)
    };
    assert!(page(4, &[Some(5), Some(7)], 7, true).is_ok(), "rising entries, more beyond them");
    assert!(page(9, &[], 9, false).is_ok(), "the empty page at the head");
    for (since, ats, last, more, case) in [
        (5, &[Some(5)][..], 5, true, "an entry at since"),
        (4, &[Some(5), Some(5)][..], 5, false, "an entry re-served"),
        (4, &[Some(7), Some(6)][..], 6, false, "two entries re-ordered"),
        (4, &[Some(5), Some(7)][..], 6, false, "a last before the final entry"),
        (4, &[Some(5)][..], 9, true, "a last past the final entry"),
        (4, &[None][..], 4, false, "an entry naming no position"),
        (9, &[][..], 9, true, "more announced with nothing on the page"),
        (9, &[][..], 12, false, "an empty page whose last is not since"),
    ] {
        assert!(matches!(page(since, ats, last, more), Err(BoardError::Malformed(_))), "{case}");
    }
}

/// A board whose every answer runs past the transport's cap.
struct Oversized;

impl Transport for Oversized {
    fn exchange(&self, _: Method, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        Err(TransportError::TooLarge { cap: 1 })
    }
}

/// AN ANSWER PAST THE CAP is no answer a typed read takes: every `/op`
/// read answers its own cannot-read — no link, no key set, no board term,
/// a deposit left standing — and the feed, `/health` and `/chain`, whose
/// answers a caller must have whole, name the transport's refusal.
#[test]
fn an_answer_past_the_cap_is_no_answer_a_typed_read_takes() {
    let board = Board::new(Box::new(Oversized));
    let (link, account) = (a("1.0.2.0.1.0.2.1"), a("1.0.2"));
    assert_eq!(board.op(&json!({ "op": "read_link", "a": link.to_string() })), Ok(Value::Null));
    assert_eq!(board.link_slots(&link, &[t_endpoint()]), Ok(None), "no link");
    assert_eq!(board.key_set(&account), Ok(None), "no key set");
    assert_eq!(board.key_set_at(5, &account), Ok(None), "no key set as of a position");
    assert_eq!(board.board_term(), Ok(None), "no board term");
    assert_eq!(board.stands_active(&link, &a("1.0.2.0.1"), t_endpoint(), &a("1.0.2.0.1.0.1.1")), Ok(true), "a deposit left standing");
    let refused = BoardError::Transport(TransportError::TooLarge { cap: 1 });
    assert_eq!(board.changes(0, None), Err(refused.clone()), "a page");
    assert_eq!(board.health(), Err(refused.clone()), "/health");
    assert_eq!(board.chain_at(5), Err(refused), "/chain");
}
