//! THE COMPOSER's FENCE: the spelling it reads a frame in — the trunk, a
//! V-spec, an I-address's split, an I-range made where its reach is
//! spellable, a tumbler and an address within their component budget, a
//! natural in either of the wire's spellings, a slot's I-span width and a
//! publication's every count alike, the wire's value faults faced as its
//! own halt — and THE
//! BOARD's BUDGETS it keeps: each pinned to the board's own where the board
//! exports it, and each held before the work it bounds, against a fake board
//! that counts the reads the composer makes — a list past the wire's, a slot
//! past its spans, a shot past its body, or past either re-insert budget
//! the board ANSWERS, the shell holding no number for those, an origin
//! past one delivery, an `image` that maps more than its extent — and, the
//! positive control beside them, a shot's body composed from the values it
//! copies in, run for run, as the signer's own builder spells it. And THE
//! COMPOSER's CONTRACT: a death signal at one of its reads the session's
//! end, and a board's refusal of one its verdict verbatim, never the
//! composer's own refusal; a frame past its precondition stopped loudly.
//! And THE WELL-KNOWN CREATION's CELL: the bytes the composer signs for a
//! `create_well_known_document`, at every slot, the very bytes
//! `skep-client`'s composer signs.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use skep_client::address::parse_address;
use skep_client::dial::{DialError, Dialer, Headers, Request, RequestHead, Response, StreamedResponse};
use skep_client::sign::{signer_from_seed, signer_from_seed_under};
use skep_client::Origin;
use skep_identity::{entry_body_publish, ShotSegmentPiece};
use skep_identity::{DepositHome, DepositKind, DepositRow, DepositSlot, MemberPositions, SlotElement};

use super::*;

/// The trunk projection over the spelling: a member drops its version
/// components, a bare document is itself, an element is taken to its
/// document, an account has none, and a text past the component budget has
/// none — counted before it is split.
#[test]
fn the_trunk_is_the_document_field_cut_to_its_first_component() {
    assert_eq!(trunk_text("1.0.1.0.1.2").as_deref(), Some("1.0.1.0.1"));
    assert_eq!(trunk_text("1.0.1.0.1").as_deref(), Some("1.0.1.0.1"));
    assert_eq!(trunk_text("1.0.1.0.69.3.1").as_deref(), Some("1.0.1.0.69"));
    assert_eq!(trunk_text("1.0.1.0.1.0.1.7").as_deref(), Some("1.0.1.0.1"));
    assert_eq!(trunk_text("1.0.1"), None);
    assert_eq!(trunk_text("1"), None);
    let deep = format!("1.0.1.0.1{}", ".1".repeat(MAX_TUMBLER_COMPONENTS - 5));
    assert_eq!(trunk_text(&deep).as_deref(), Some("1.0.1.0.1"), "a member at the budget");
    assert_eq!(trunk_text(&format!("{deep}.1")), None, "one component past it");
}

/// THE COMPOSER reads a frame as the wire spells it: an insert's `values`
/// the wire's forms refuse are its halt, each fault faced in its own words;
/// a V-spec's span reads as `(from, width)`; an I-address splits at its last
/// component; the eleven kinds are the checked set, each named by its own
/// spelling, a frame of them wanting the shell's attest where none rides it;
/// and a run `image` answers is a content extent, its width zeros but at its
/// last component.
#[test]
fn the_composer_reads_a_frame_as_the_wire_spells_it() {
    let insert = |values: Value| insert_terms(&json!({"op": "insert", "doc": "1.0.1.0.1", "values": values})).map(drop).unwrap_err().to_string();
    assert!(insert(json!([7])).contains("not the wire's forms"), "{}", insert(json!([7])));
    assert!(insert(json!(["a".repeat(MAX_INSERT_VALUES + 1)])).contains(&format!("more than {MAX_INSERT_VALUES} values")));
    assert_eq!(v_spec(&json!({"start": "1.6", "width": "0.2"})), Some((6, 2)));
    assert_eq!(v_spec(&json!({"start": "2.6", "width": "0.2"})), None);
    assert_eq!(split_i("1.0.1.0.1.0.1.4"), Some(("1.0.1.0.1.0.1", 4)));
    assert_eq!(split_i("1.0.1.0.1.0.1.x"), None);
    assert!(in_checked_set("publish") && !in_checked_set("delete"));
    assert_eq!(CheckedKind::ALL.map(CheckedKind::as_str), ["create_new_document", "fork", "version", "create_well_known_document", "insert", "publish", "make_link", "emit", "nullify", "assert_sup", "edit_link"]);
    assert!(in_checked_set("create_well_known_document") && wants_attest(&json!({"op": "create_well_known_document", "account": "1.0.1", "slot": 2})), "the eleventh kind, at every slot");
    assert!(CheckedKind::ALL.into_iter().all(|kind| CheckedKind::named(kind.as_str()) == Some(kind)));
    assert!(wants_attest(&json!({"op": "publish"})));
    assert!(!wants_attest(&json!({"op": "publish", "attest": {"alg": "x", "sig": "00"}})), "a page-supplied attest stands as it is");
    assert!(!wants_attest(&json!({"op": "delete"})) && !wants_attest(&json!({})));
    let span = extent_span("1.0.1.0.1.0.1.4", 3).unwrap();
    assert_eq!((span.start().to_string(), span.width().to_string()), ("1.0.1.0.1.0.1.4".to_string(), "0.0.0.0.0.0.0.3".to_string()));
}

/// AN I-RANGE is made where its reach is spellable and nowhere else: three
/// positions from `prefix.1` walk 1, 2, 3, and a range whose reach passes
/// `u64::MAX` is none — the one bound every walk of its positions stands on,
/// whether the range came from an `image` run or a shot's copied run.
#[test]
fn an_i_range_is_made_where_its_reach_is_spellable() {
    let range = IRange::new("1.0.1.0.64.0.1", 1, 3).expect("a spellable range");
    assert_eq!((range.positions().collect::<Vec<_>>(), range.width()), (vec![1, 2, 3], 3));
    assert_eq!(IRange::new("1.0.1.0.64.0.1", u64::MAX - 2, 2).map(IRange::width), Some(2), "a reach at u64::MAX is spellable");
    assert!(IRange::new("1.0.1.0.64.0.1", u64::MAX, 1).is_none(), "a reach past it is none");
    let image = json!({"i_start": "1.0.1.0.64.0.1.18446744073709551615", "width": "1"});
    assert!(image_run(&image, "1.0.1.0.64").unwrap_err().to_string().contains("is no I-extent"), "an `image` run whose reach passes it is refused");
}

/// THE BOARD's BUDGETS the board exports are the shell's: the frame cap the
/// daemon's transport refuses a longer `/op` body by and M7's per-slot span
/// budget. The codec's own three — a wire list, an insert's values, a
/// tumbler's components — are private to the daemon, and pinned by its
/// behaviour in the shell's suite. M5's two re-insert budgets are no
/// constant here: the composer reads them off the board's price
/// (`a_shots_reinsert_is_held_to_the_budgets_the_board_answers`).
#[test]
fn the_budgets_are_the_boards() {
    assert_eq!(MAX_FRAME_BYTES, skepd::body_cap("POST", "/op"));
    assert_eq!(MAX_SLOT_SPANS, skep_links::MAX_SLOT_SPANS);
    assert_eq!(MAX_COPIED_POSITIONS, (MAX_FRAME_BYTES / 4) as u64);
}

/// The room a burst keeps for its attest holds the attest of every row a
/// key signs under, measured as the composer attaches it: the member's
/// bytes in the frame, at the row's own token and signature.
#[test]
fn the_attest_room_holds_every_rows_attest() {
    let frame = json!({"op": "insert", "doc": "1.0.1.0.1"});
    let bare = frame.to_string().len();
    for row in SIG_ALGS {
        let signer = signer_from_seed_under(row.tag, &[7; 32]).expect("every row signs");
        let mut attested = frame.clone();
        attested["attest"] = json!({"alg": signer.public_key().alg(), "sig": sig_hex(&signer.sign(b"the entry frame"))});
        let added = attested.to_string().len() - bare;
        assert!(added <= attest_room(), "{}: the attest adds {added} bytes, past the room's {}", row.token, attest_room());
    }
}

/// A tumbler and an address the composer reads are held to their component
/// budget — counted before a component is converted: one at the budget
/// read, one past it refused, an address past it the composer's halt.
#[test]
fn a_tumbler_and_an_address_are_read_within_the_component_budget() {
    let at = format!("1{}", ".1".repeat(MAX_TUMBLER_COMPONENTS - 1));
    assert!(tumbler(&at).is_some() && tumbler(&format!("{at}.1")).is_none());
    assert!(addr(&at, "home").is_ok(), "an address at the budget");
    assert!(addr(&format!("{at}.1"), "home").is_err());
}

// ── THE COMPOSER's READS, against a fake board ──────────────────────────────

/// One origin document as the fake stores it: its positions' I-addresses, a
/// prefix and a first last component, and the item delivered at each.
struct Stored {
    prefix: &'static str,
    first: u64,
    items: Vec<Value>,
}

/// A board under test for the composer's reads: each origin's positions,
/// answered by `retrieve_doc_v_span_set`, `image` and `retrieve_v` — or,
/// where armed, an extent or an `image` answer of its own, or the death
/// signal on every answer — a shot's price, answered by `publish_cost` as
/// the test scripts it, and every op dialed, recorded by its name.
#[derive(Default)]
struct Fake {
    origins: HashMap<&'static str, Stored>,
    extents: HashMap<&'static str, u64>,
    images: HashMap<&'static str, Value>,
    /// Documents of this many one-position runs — position `k` at
    /// `<doc>.0.1.<2k>`, none I-adjacent to the next — whose `image` the
    /// fake answers as the board pages one: the runs that fit under
    /// `image_page` with the go-on, and the rest to its continuation.
    paged: HashMap<&'static str, u64>,
    /// The links a retraction tuple stands for: `find_links_ftt` over the
    /// retraction class and one of these as `to` answers one hit.
    retracted: Vec<&'static str>,
    /// The active supersession claims standing, `(old, home)`: `in_claims`
    /// at `old` answers each as a claim homed in `home`, whose owner
    /// `effective_owner` answers as the home's account prefix.
    claims: Vec<(&'static str, &'static str)>,
    /// What `publish_cost` answers, as the test scripts it; where it
    /// scripts none, [`Fake::priced`] at one unit and the budgets a board
    /// of this build states.
    cost: Mutex<Option<Value>>,
    closed: AtomicBool,
    dialed: Mutex<Vec<String>>,
}

impl Fake {
    /// The origin `doc` holding `text`, one item a byte, its I-addresses
    /// from `prefix.first`.
    fn text(mut self, doc: &'static str, prefix: &'static str, first: u64, text: &str) -> Fake {
        let items = text.chars().map(|c| json!({"content": c.to_string()})).collect();
        self.origins.insert(doc, Stored { prefix, first, items });
        self
    }

    /// The ops dialed, in order.
    fn dialed(&self) -> Vec<String> {
        self.dialed.lock().unwrap().clone()
    }

    /// A `publish_cost` answer of `units` units at the two re-insert
    /// budgets given, its other figures inside their own.
    fn priced(units: u64, unit_budget: u64, position_budget: u64) -> Value {
        json!({"resp": "publish_cost", "as_of": 1, "homes": 1, "entries": 0, "rewindow": 0, "fence": 1, "staged_bytes": 2_000, "units": units, "read_budget": 65_536, "byte_budget": 67_108_864, "unit_budget": unit_budget, "position_budget": position_budget})
    }

    /// Scripts the next `publish_cost` answers.
    fn answer_price(&self, cost: Value) {
        *self.cost.lock().unwrap() = Some(cost);
    }
}

/// The last component of a dotted text: `"0.<n>"` and `"1.<n>"` read back
/// as `n`.
fn last_component(text: &str) -> usize {
    text.rsplit('.').next().and_then(|n| n.parse().ok()).unwrap_or(0)
}

fn ok(v: Value) -> Response {
    Response { status: 200, headers: Headers::default(), body: v.to_string().into_bytes() }
}

impl Dialer for Fake {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        let frame: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let op = frame["op"].as_str().unwrap_or("").to_string();
        self.dialed.lock().unwrap().push(op.clone());
        if self.closed.load(Ordering::SeqCst) {
            return Ok(Response { status: 200, headers: Headers(vec![("Skepd-Session".into(), "closed".into())]), body: Vec::new() });
        }
        let unknown = || ok(json!({"resp": "rejected", "code": "doc_not_registered", "disposition": "reorder"}));
        Ok(match op.as_str() {
            "retrieve_doc_v_span_set" => {
                let doc = frame["doc"].as_str().unwrap_or("");
                let extent = self.extents.get(doc).copied().or_else(|| self.origins.get(doc).map(|stored| stored.items.len() as u64));
                match extent {
                    Some(n) => ok(json!({"resp": "span_set", "set": [{"start": "1.1", "width": format!("0.{n}")}]})),
                    None => unknown(),
                }
            }
            "image" => {
                let doc = frame["d"].as_str().unwrap_or("");
                let (from, width) = (last_component(frame["region"][0]["start"].as_str().unwrap_or("")), last_component(frame["region"][0]["width"].as_str().unwrap_or("")));
                if let Some((doc, count)) = self.paged.get_key_value(doc) {
                    let (from, until) = (from as u64, (from as u64 + width as u64).min(count + 1));
                    assert!(frame["cur"].is_null() || frame["cur"]["at"] == from.to_string(), "a continuation begins where its go-on says: {frame}");
                    let page = (until - from).min(MAX_SLOT_SPANS as u64);
                    let runs: Vec<Value> = (from..from + page).map(|k| json!({"i_start": format!("{doc}.0.1.{}", 2 * k), "width": "1"})).collect();
                    return Ok(if from + page < until {
                        ok(json!({"resp": "image_page", "as_of": 1, "ispans": runs, "next": {"at": (from + page).to_string(), "surface": doc, "arranged_at": null}}))
                    } else {
                        ok(json!({"resp": "runs", "as_of": 1, "runs": runs}))
                    });
                }
                match (self.images.get(doc), self.origins.get(doc)) {
                    (Some(runs), _) => ok(json!({"resp": "image", "runs": runs})),
                    (None, Some(stored)) => ok(json!({"resp": "image", "runs": [{"i_start": format!("{}.{}", stored.prefix, stored.first + from as u64 - 1), "width": width.to_string()}]})),
                    _ => unknown(),
                }
            }
            "retrieve_v" => {
                let spec = &frame["specs"][0];
                let doc = spec["doc"].as_str().unwrap_or("");
                let (from, width) = (last_component(spec["span"]["start"].as_str().unwrap_or("")), last_component(spec["span"]["width"].as_str().unwrap_or("")));
                match self.origins.get(doc) {
                    Some(stored) => ok(json!({"resp": "delivery", "items": stored.items.iter().skip(from - 1).take(width).collect::<Vec<_>>()})),
                    None => unknown(),
                }
            }
            "find_links_ftt" => {
                let to = frame["q"]["to"][0]["start"].as_str().unwrap_or("");
                let ty = frame["q"]["ty"][0]["start"].as_str().unwrap_or("");
                let hits: Vec<String> = if ty == T_RETRACTION && self.retracted.contains(&to) { vec![format!("{}.0.2.9", to.rsplit_once(".0.2.").map_or(to, |(home, _)| home))] } else { Vec::new() };
                ok(json!({"resp": "addrs", "addrs": hits, "as_of": 1}))
            }
            "in_claims" => {
                let y = frame["y"].as_str().unwrap_or("");
                let claims: Vec<Value> = self.claims.iter().filter(|(old, _)| *old == y).map(|(old, home)| json!({"active": true, "claim": format!("{home}.0.2.3"), "home": home, "new": format!("{old}.1"), "old": old})).collect();
                ok(json!({"resp": "claims", "as_of": 1, "claims": claims}))
            }
            "publish_cost" => {
                let scripted = self.cost.lock().unwrap().clone();
                ok(scripted.unwrap_or_else(|| Fake::priced(1, skep_arrangement::MAX_REINSERTED_UNITS as u64, skep_arrangement::MAX_REINSERTED_VALUES as u64)))
            }
            "effective_owner" => {
                let a = frame["addr"].as_str().unwrap_or("");
                let prefix = a.split(".0.").next().map(|node| format!("{node}.0.{}", a.split(".0.").nth(1).unwrap_or("0"))).unwrap_or_default();
                ok(json!({"resp": "owner", "prefix": prefix, "principal": 1}))
            }
            _ => ok(json!({"resp": "ack"})),
        })
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// The ground a composer reads from: the fake behind a board, a session's
/// token and a key.
struct Ground {
    fake: Arc<Fake>,
    board: Board,
    token: Token,
    signer: Box<dyn Signer>,
}

impl Ground {
    fn over(fake: Fake) -> Ground {
        let fake = Arc::new(fake);
        let board = Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&fake));
        Ground { fake, board, token: Token::parse(&"9f".repeat(16)).unwrap(), signer: Box::new(signer_from_seed(&[7; 32])) }
    }

    fn composer(&self) -> Composer<'_> {
        Composer { board: &self.board, token: &self.token, signer: &*self.signer, account: "1.0.1", board_term: BoardTerm { log_position: 1, chain: [0xab; 32] } }
    }
}

/// `n` runs of an `image` answer, each one position wide.
fn image_runs(n: usize) -> Value {
    Value::Array((1..=n).map(|k| json!({"i_start": format!("1.0.1.0.1.0.1.{k}"), "width": "1"})).collect())
}

/// A V-spec over `source`'s first position.
fn vspec(source: &str) -> Value {
    json!({"source": source, "span": {"start": "1.1", "width": "0.1"}})
}

/// A SLOT is held to the wire's list before its first read — a V-spec list,
/// an address list or an I-span list one past [`MAX_WIRE_LIST`] refused with
/// no op dialed, one at it composed — and to [`MAX_SLOT_SPANS`] as it
/// resolves: a source whose `image` answers one span past the budget refused
/// at the first read, one at it composed (the mutants that drop either check
/// compose a slot the store refuses, after reads the frame should never have
/// cost).
#[test]
fn a_slot_is_held_to_the_wire_list_and_its_span_budget() {
    let mut fake = Fake::default();
    fake.images.insert("1.0.1.0.70", image_runs(MAX_SLOT_SPANS + 1));
    fake.images.insert("1.0.1.0.71", image_runs(MAX_SLOT_SPANS));
    let g = Ground::over(fake);
    let c = g.composer();
    let past = Value::Array(vec![vspec("1.0.1.0.71"); MAX_WIRE_LIST + 1]);
    assert!(c.slot(&past, "from").is_err());
    assert!(c.slot(&json!({"resolve": past}), "successor.ty").is_err());
    assert!(c.slot(&json!({"addrs": vec!["1.0.1.0.1"; MAX_WIRE_LIST + 1]}), "to").is_err());
    assert!(g.fake.dialed().is_empty(), "nothing is read for a list past the wire's: {:?}", g.fake.dialed());
    assert_eq!(c.slot(&json!({"addrs": vec!["1.0.1.0.1"; MAX_WIRE_LIST]}), "to").unwrap().len(), MAX_WIRE_LIST);
    let refused = c.slot(&json!([vspec("1.0.1.0.70"), vspec("1.0.1.0.71")]), "from").unwrap_err();
    assert!(refused.to_string().contains("spans"), "{refused}");
    assert_eq!(g.fake.dialed(), ["image"], "refused at the first read past the budget");
    assert_eq!(c.slot(&json!([vspec("1.0.1.0.71")]), "from").unwrap().len(), MAX_SLOT_SPANS);
    let ispans = |n: usize| json!({"spans": vec![json!({"start": "1.0.1.0.64.0.1.1", "width": "1"}); n]});
    g.fake.dialed.lock().unwrap().clear();
    assert!(c.slot(&ispans(MAX_WIRE_LIST + 1), "to").is_err());
    assert_eq!(c.slot(&ispans(MAX_WIRE_LIST), "to").unwrap().len(), MAX_WIRE_LIST, "an I-span list at the wire's is composed");
    assert!(g.fake.dialed().is_empty(), "an I-span slot reads nothing: {:?}", g.fake.dialed());
}

/// A LINK SLOT in the I-span form is signed as stored (wire.md §Links
/// (writes)): each span `width` positions from its `start`, the content
/// extent verbatim, no read made — a `make_link`'s `to` and an `edit_link`
/// successor's `to` alike, each body the signer's own builder over the same
/// spans — its `width` a natural in either of the wire's spellings, so
/// integer widths, and the two spellings mixed, sign the body decimal
/// strings sign; and a span of zero width in either spelling, or of a width
/// that is no natural — a decimal fraction, a negative or fractional number
/// — is the composer's halt naming the span, nothing read (the mutant that
/// reads no `{"spans"}` slot refuses every follower's mark unsent,
/// `attest_not_composed`; the one that reads a width as a string alone
/// refuses an agent's integer width, which the board takes, unsent).
#[test]
fn a_link_slot_in_the_i_span_form_is_signed_as_stored() {
    let g = Ground::over(Fake::default());
    let c = g.composer();
    let a = |text: &str| parse_address(text).unwrap();
    let to_spans = |four: Value, one: Value| json!({"spans": [{"start": "1.0.1.0.64.0.1.3", "width": four}, {"start": "1.0.1.0.64.0.1.9", "width": one}]});
    let ty = json!({"addrs": ["1.1.0.1.0.1.0.3.13"]});
    let spans = [extent_span("1.0.1.0.64.0.1.3", 4).unwrap(), extent_span("1.0.1.0.64.0.1.9", 1).unwrap()];
    let ty_unit = [unit_span(&a("1.1.0.1.0.1.0.3.13"))];
    let slots = LinkSlots { from: EntrySlot(&[]), to: EntrySlot(&spans), ty: EntrySlot(&ty_unit) };
    for (cell, to) in [("decimal widths", to_spans(json!("4"), json!("1"))), ("integer widths", to_spans(json!(4), json!(1))), ("the two spellings mixed", to_spans(json!(4), json!("1")))] {
        let make_link = json!({"op": "make_link", "home": "1.0.1.0.1", "from": {"addrs": []}, "to": to, "ty": ty});
        let (term, body) = c.doc_term_and_body(CheckedKind::MakeLink, &make_link).unwrap_or_else(|e| panic!("{cell}: {e}"));
        assert_eq!((term.as_doc_term(), body), (DocTerm::One(&a("1.0.1.0.1")), entry_body_make_link(slots)), "{cell}");
        let edit_link = json!({"op": "edit_link", "original": "1.0.1.0.1.0.2.1", "d_s": "1.0.1.0.1", "d_a": "1.0.1.0.65", "successor": {"from": {"spans": []}, "to": to, "ty": ty}});
        let (_, body) = c.doc_term_and_body(CheckedKind::EditLink, &edit_link).unwrap_or_else(|e| panic!("{cell}: {e}"));
        assert_eq!(body, entry_body_edit_link(slots, &unit_span(&a("1.0.1.0.1.0.2.1"))), "{cell}");
    }
    let no_span = [("a zero width", json!("0")), ("an integer zero", json!(0)), ("a width of no decimal", json!("0.4")), ("a negative integer", json!(-1)), ("a fractional number", json!(4.5))];
    for (cell, width) in no_span {
        let refused = c.slot(&json!({"spans": [{"start": "1.0.1.0.64.0.1.3", "width": width}]}), "to").unwrap_err();
        assert!(refused.to_string().contains("`to` span"), "{cell}: {refused}");
    }
    assert!(g.fake.dialed().is_empty(), "the form reads nothing: {:?}", g.fake.dialed());
}

/// A run copied in from `origin` at `i_start`, `width` wide.
fn run(origin: &str, i_start: &str, width: u64) -> Value {
    json!({"origin": origin, "i_start": i_start, "width": width.to_string()})
}

/// A SHOT is held to its ARITHMETIC before any read: runs past the wire's
/// list, the copied positions past what a body under the budget can carry,
/// and a count past `be64` (a window of width 2^64 − 1 and a run after it —
/// a panic in the signer's own builder) are each refused with nothing read,
/// the board's price among the reads not made; a shot that copies in none
/// of its draft's words asks no price at all.
#[test]
fn a_shot_is_held_to_its_arithmetic_before_any_read() {
    let g = Ground::over(Fake::default());
    let c = g.composer();
    let shot = |runs: Vec<Value>| json!({"op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64", "runs": runs});
    let draft_run = |width: u64| run("1.0.1.0.64", "1.0.1.0.64.0.1.1", width);
    let cells = [
        ("runs past the wire's list", shot(vec![draft_run(1); MAX_WIRE_LIST + 1]), "elements"),
        ("the copied positions past a body", shot(vec![run("1.0.1.0.1.1", "1.0.1.0.1.1.0.1.1", MAX_COPIED_POSITIONS + 1)]), "copies in"),
        ("the draft's positions past a body", shot(vec![draft_run(MAX_COPIED_POSITIONS + 1)]), "copies in"),
        ("a count past be64", shot(vec![run("1.0.9.0.1", "1.0.9.0.1.0.1.1", u64::MAX), run("1.0.9.0.1", "1.0.9.0.1.0.1.1", 1)]), "2^64"),
    ];
    for (cell, frame, says) in cells {
        let refused = c.publish_body(&frame, "1.0.1.0.1").unwrap_err();
        assert!(refused.to_string().contains(says), "{cell}: {refused}");
        assert!(g.fake.dialed().is_empty(), "{cell}: nothing is read: {:?}", g.fake.dialed());
    }
    // The trunk's own words alone, by reference: nothing of the draft's is
    // re-inserted, so no price is asked — the first read is the values'.
    let own = shot(vec![run("1.0.1.0.1", "1.0.1.0.1.0.1.1", 2)]);
    let _ = c.publish_body(&own, "1.0.1.0.1");
    assert_eq!(g.fake.dialed(), ["retrieve_doc_v_span_set"], "a shot re-inserting nothing asks no price");
}

/// A SHOT's RE-INSERT IS HELD TO THE BUDGETS THE BOARD ANSWERS, and to no
/// number of the shell's. A shot copying in its draft's words asks the
/// board ONE `publish_cost` of its own members — no `id`, no `attest` —
/// before it reads a value, and is held to that answer: its distinct draft
/// positions (a run named twice counted once, two disjoint runs together)
/// to the positions budget the board states, and the units the board counts
/// them as to its units budget. A draft of 131,073 distinct positions — one
/// past the positions budget as it once stood — in one unit is composed
/// on, read for its values; the same shot at a board answering a smaller
/// positions budget, or more units than its units budget, is refused with
/// the price its only read. A board whose answer is no price, and one that
/// refuses the read, halt the composer the same way: nothing is signed over
/// a budget the shell guessed.
#[test]
fn a_shots_reinsert_is_held_to_the_budgets_the_board_answers() {
    let (units, positions) = (skep_arrangement::MAX_REINSERTED_UNITS as u64, skep_arrangement::MAX_REINSERTED_VALUES as u64);
    let g = Ground::over(Fake::default());
    let c = g.composer();
    let shot = |runs: Vec<Value>| json!({"op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64", "id": "k-1", "runs": runs});
    let draft_run = |first: u64, width: u64| run("1.0.1.0.64", &format!("1.0.1.0.64.0.1.{first}"), width);
    // What the composer answers the shot of `runs`, and the ops it dialed.
    let composed = |runs: Vec<Value>| {
        g.fake.dialed.lock().unwrap().clear();
        let refused = c.publish_body(&shot(runs), "1.0.1.0.1").unwrap_err().to_string();
        (refused, g.fake.dialed())
    };
    let price_alone = vec!["publish_cost".to_string()];
    let read_on = vec!["publish_cost".to_string(), "retrieve_doc_v_span_set".to_string()];
    // At the budgets a board of this build states: 131,073 positions in one
    // unit pass both, and the draft is read for its values (the fake holds
    // none, which is where this composition ends).
    let (refused, dialed) = composed(vec![draft_run(1, (1 << 17) + 1)]);
    assert!(!refused.contains("re-inserts"), "inside both budgets: {refused}");
    assert_eq!(dialed, read_on, "the price, then the values");
    // The positions budget is the answer's: at it, and one past it.
    let (refused, dialed) = composed(vec![draft_run(1, positions)]);
    assert!(!refused.contains("re-inserts"), "at the positions budget: {refused}");
    assert_eq!(dialed, read_on);
    let (refused, dialed) = composed(vec![draft_run(1, positions), draft_run(positions + 1, 1)]);
    assert!(refused.contains(&format!("re-inserts {} distinct values from its draft, past the board's {positions}", positions + 1)), "{refused}");
    assert_eq!(dialed, price_alone, "refused with the price its only read");
    let (refused, _) = composed(vec![draft_run(1, positions), draft_run(1, 1)]);
    assert!(!refused.contains("re-inserts"), "a run named twice is counted once: {refused}");
    // Another board, other budgets: the same shots, another verdict.
    g.fake.answer_price(Fake::priced(3, units, 10));
    let (refused, dialed) = composed(vec![draft_run(1, 11)]);
    assert!(refused.contains("re-inserts 11 distinct values from its draft, past the board's 10"), "{refused}");
    assert_eq!(dialed, price_alone);
    let (refused, dialed) = composed(vec![draft_run(1, 10)]);
    assert!(!refused.contains("re-inserts"), "{refused}");
    assert_eq!(dialed, read_on);
    // The units are the board's count, held to the board's budget.
    g.fake.answer_price(Fake::priced(units + 1, units, positions));
    let (refused, dialed) = composed(vec![draft_run(1, units + 1)]);
    assert!(refused.contains(&format!("as {} units, past the board's {units}", units + 1)), "{refused}");
    assert_eq!(dialed, price_alone);
    g.fake.answer_price(Fake::priced(5, 4, positions));
    assert!(composed(vec![draft_run(1, 5)]).0.contains("as 5 units, past the board's 4"));
    // An answer that is no price, and a refusal of the read: the halt.
    g.fake.answer_price(json!({"resp": "publish_cost", "as_of": 1, "homes": 1}));
    let (refused, dialed) = composed(vec![draft_run(1, 5)]);
    assert!(refused.contains("is no price"), "{refused}");
    assert_eq!(dialed, price_alone);
    g.fake.answer_price(json!({"resp": "rejected", "op": "publish_cost", "code": "withheld", "disposition": "permanent", "site": {"addr": "1.0.1.0.64"}}));
    let (refused, dialed) = composed(vec![draft_run(1, 5)]);
    assert!(refused.contains("withheld"), "the board's own verdict: {refused}");
    assert_eq!(dialed, price_alone);
}

/// THE READ-BACK is held to what one delivery can carry and to the map the
/// origin's `image` answers: an extent past the answer cap refused before
/// `image` is asked, an `image` mapping more positions than the extent (a
/// width a board chose) refused before `retrieve_v` is asked, and the
/// values kept held to the body budget the shot's copied-in values share
/// (the mutants that walk an overshooting map, or keep past the budget,
/// allocate for what no body could carry).
#[test]
fn a_read_back_is_held_to_its_extent_its_map_and_the_body_budget() {
    let mut fake = Fake::default().text("1.0.1.0.64", "1.0.1.0.64.0.1", 1, "abc").text("1.0.1.0.65", "1.0.1.0.65.0.1", 1, "xyz");
    fake.extents.insert("1.0.1.0.66", MAX_ANSWER_BYTES as u64 + 1);
    fake.images.insert("1.0.1.0.65", json!([{"i_start": "1.0.1.0.65.0.1.1", "width": "1000000"}]));
    let g = Ground::over(fake);
    let c = g.composer();
    let read = |origin: &'static str, spent: &mut usize| {
        let mut wanted = Wanted::new(origin);
        wanted.want(IRange::new(if origin == "1.0.1.0.65" { "1.0.1.0.65.0.1" } else { "1.0.1.0.64.0.1" }, 1, 3).expect("a spellable range"));
        c.read_back(wanted, spent)
    };
    assert!(read("1.0.1.0.66", &mut 0).unwrap_err().to_string().contains("more than one delivery"));
    assert_eq!(g.fake.dialed(), ["retrieve_doc_v_span_set"], "no image asked past the answer cap");
    g.fake.dialed.lock().unwrap().clear();
    assert!(read("1.0.1.0.65", &mut 0).unwrap_err().to_string().contains("maps more positions"));
    assert_eq!(g.fake.dialed(), ["retrieve_doc_v_span_set", "image"], "no values asked past the map");
    let mut spent = MAX_FRAME_BYTES - 2 * (4 + 1) - 1;
    assert!(read("1.0.1.0.64", &mut spent).is_err(), "the third value passes the body budget");
    let mut spent = 0;
    let read_back = read("1.0.1.0.64", &mut spent).unwrap();
    assert_eq!((read_back.value("1.0.1.0.64.0.1", 2), spent), (Some(&b"b"[..]), 3 * (4 + 1)));
}

/// **The composer reads a long image whole**, both of its reads. An origin of
/// 5,000 runs is read back through its whole map, two `image` frames, and
/// the value at a position on the second page is the one kept (the mutant
/// that takes the first page for the image maps fewer positions than the
/// extent and composes no body). A V-spec slot over the same 5,000 runs is
/// resolved whole, two frames, and refused at the slot's span budget on the
/// run past it — its own cap, counted over every run, never `image`
/// answering none.
#[test]
fn the_composer_reads_an_image_past_one_page_whole() {
    let long = "1.0.1.0.64";
    let mut fake = Fake::default().text(long, "1.0.1.0.64.0.1", 1, &"q".repeat(4_499));
    fake.origins.get_mut(long).expect("the origin").items.extend([json!({"content": "Z"}), json!({"content": "q"})].into_iter().cycle().take(501));
    fake.paged.insert(long, 5_000);
    let g = Ground::over(fake);
    let c = g.composer();
    let mut wanted = Wanted::new(long);
    wanted.want(IRange::new("1.0.1.0.64.0.1", 9_000, 1).expect("a spellable range"));
    let mut spent = 0;
    let read_back = c.read_back(wanted, &mut spent).expect("read back through the whole map");
    assert_eq!(read_back.value("1.0.1.0.64.0.1", 9_000), Some(&b"Z"[..]), "the 4,500th position's value, on the second page");
    assert_eq!(g.fake.dialed(), ["retrieve_doc_v_span_set", "image", "image", "retrieve_v"], "the map in two frames");
    g.fake.dialed.lock().unwrap().clear();
    let whole = json!([{"source": long, "span": {"start": "1.1", "width": "0.5000"}}]);
    let refused = c.slot(&whole, "from").unwrap_err();
    assert!(refused.to_string().contains("slot resolves to more than 4096 spans"), "the slot's own budget, over every run: {refused}");
    assert_eq!(g.fake.dialed(), ["image", "image"], "the source's image whole, two frames");
    let within = json!([{"source": long, "span": {"start": "1.4090", "width": "0.20"}}]);
    assert_eq!(c.slot(&within, "from").expect("a region across the page's edge").len(), 20);
}

/// THE SHOT's BODY, the positive control: runs copied in from the staging
/// draft and from a member of the shot's own trunk — the draft's twice,
/// overlapping — a window onto another document, and a base, composed from
/// the values each origin's own arrangement holds, read once per origin,
/// exactly as the signer's builder spells the same pieces.
#[test]
fn a_shots_body_is_composed_from_the_values_it_copies_in() {
    let fake = Fake::default().text("1.0.1.0.64", "1.0.1.0.64.0.1", 1, "abcd").text("1.0.1.0.1.1", "1.0.1.0.1.1.0.1", 1, "xyz");
    let g = Ground::over(fake);
    let frame = json!({
        "op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64", "base": "1.0.1.0.1.1", "base_extent": "3",
        "runs": [
            run("1.0.1.0.64", "1.0.1.0.64.0.1.3", 2),
            run("1.0.9.0.1", "1.0.9.0.1.0.1.5", 3),
            run("1.0.1.0.1.1", "1.0.1.0.1.1.0.1.1", 2),
            run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 3),
        ],
    });
    let body = g.composer().publish_body(&frame, "1.0.1.0.1").unwrap();
    let window: Address = parse_address("1.0.9.0.1.0.1.5").unwrap();
    let member: Address = parse_address("1.0.1.0.1.1").unwrap();
    let value = |v: &'static [u8]| ShotSegmentPiece::Value(v);
    let pieces = [value(b"c"), value(b"d"), ShotSegmentPiece::Window { start: &window, width: NonZeroU64::new(3).unwrap() }, value(b"x"), value(b"y"), value(b"a"), value(b"b"), value(b"c")];
    let spelled = entry_body_publish(pieces, Some(ShotBase { member: &member, extent: 3 }));
    assert_eq!(body.as_bytes(), spelled.as_bytes());
    let reads = g.fake.dialed();
    assert_eq!(reads.iter().filter(|op| *op == "retrieve_v").count(), 2, "one read per origin: {reads:?}");
}

/// A PUBLICATION's NATURALS read in either of the wire's spellings (wire.md
/// §Value encodings): a shot whose runs' widths, whose `base_extent`, whose
/// deposit's I-span width or whose member end's positions are JSON integers
/// signs the body the same frame in decimal strings signs — each kind
/// spelled apart in a cell of its own, so the mutant that reads any one of
/// them as a string alone refuses its cell's frame, which the board takes,
/// unsent; and a `base_extent` that is no natural is the composer's halt
/// naming it, never a base without its extent, with nothing read.
#[test]
fn a_publications_naturals_read_in_either_of_the_wire_spellings() {
    let g = Ground::over(Fake::default().text("1.0.1.0.64", "1.0.1.0.64.0.1", 1, "abcd").text("1.0.1.0.1.1", "1.0.1.0.1.1.0.1", 1, "xyz"));
    let c = g.composer();
    let decimal: fn(u64) -> Value = |n| Value::from(n.to_string());
    let integer: fn(u64) -> Value = Value::from;
    // The positive control's shot less its last run, and a deposit of two
    // copies: each kind of natural the frame names spelled by its own hand.
    let frame = |widths: fn(u64) -> Value, extent: fn(u64) -> Value, ispan: fn(u64) -> Value, member: fn(u64) -> Value| {
        let ty = json!({"addrs": ["1.1.0.1.0.1.0.3.13"]});
        json!({
            "op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64", "base": "1.0.1.0.1.1", "base_extent": extent(3),
            "runs": [
                {"origin": "1.0.1.0.64", "i_start": "1.0.1.0.64.0.1.3", "width": widths(2)},
                {"origin": "1.0.9.0.1", "i_start": "1.0.9.0.1.0.1.5", "width": widths(3)},
                {"origin": "1.0.1.0.1.1", "i_start": "1.0.1.0.1.1.0.1.1", "width": widths(2)},
            ],
            "links": [
                {"home": "1.0.1.0.66", "from": {"spans": [{"start": "1.0.1.0.66.0.1.1", "width": ispan(2)}]}, "to": {"addrs": []}, "ty": ty},
                {"home": "member", "from": {"member": [{"ordinal": member(1), "width": member(2)}, {"ordinal": member(4), "width": member(1)}]}, "to": {"addrs": []}, "ty": ty},
            ],
        })
    };
    let (_, decimals) = c.doc_term_and_body(CheckedKind::Publish, &frame(decimal, decimal, decimal, decimal)).unwrap();
    for (cell, spelled) in [
        ("the runs' widths", frame(integer, decimal, decimal, decimal)),
        ("the base's extent", frame(decimal, integer, decimal, decimal)),
        ("the I-span end's width", frame(decimal, decimal, integer, decimal)),
        ("the member end's positions", frame(decimal, decimal, decimal, integer)),
        ("every natural", frame(integer, integer, integer, integer)),
    ] {
        let (_, body) = c.doc_term_and_body(CheckedKind::Publish, &spelled).unwrap_or_else(|e| panic!("{cell} as integers: {e}"));
        assert_eq!(body.as_bytes(), decimals.as_bytes(), "{cell} as integers sign the body their decimal strings sign");
    }
    g.fake.dialed.lock().unwrap().clear();
    for (cell, extent) in [("a negative integer", json!(-1)), ("a fractional number", json!(1.5)), ("a decimal fraction", json!("0.3")), ("a list", json!(["3"]))] {
        let mut shot = frame(integer, integer, integer, integer);
        shot["base_extent"] = extent;
        let refused = c.publish_body(&shot, "1.0.1.0.1").unwrap_err();
        assert!(refused.to_string().contains("`base_extent` is no natural"), "{cell}: {refused}");
    }
    assert!(g.fake.dialed().is_empty(), "a `base_extent` that is no natural is refused before any read: {:?}", g.fake.dialed());
}

/// THE DEPOSIT ROWS (the link-sets design §5.7; lane S3): a `publish` frame
/// carrying `links`, `retract` and `read_with` signs the shot's body with
/// one group per public deposit behind it, per home in the signed order —
/// the member by tag first, then every other home in address order; inside
/// a home the copies, the retractions, the read-withs — each end as spelled
/// (an address as its unit span, a tag as the tag, an I-span verbatim, a
/// member-position row as given), a retraction `from` its home `to` its
/// target under the retraction class, a read-with `from` the trunk `to` the
/// set under the read-with class; a `retract` of a link whose retraction
/// stands on the board is read as skipped and spells no row, exactly as the
/// signer's own builder spells the same rows. The mint form's term is the
/// account, its claim row homed in the edition by tag, `from` the edition,
/// `to` the draft; `claim` at the document form (skep #692) is the claim
/// row first in `doc`'s own group, homed by ADDRESS and `from` the edition's
/// unit span — the signer asking nothing of the edition's members, which
/// are the board's to refuse.
#[test]
fn a_publications_deposit_rows_follow_the_signed_order_and_a_standing_retraction_is_skipped() {
    let mut fake = Fake::default().text("1.0.1.0.64", "1.0.1.0.64.0.1", 1, "abc");
    fake.retracted.push("1.0.1.0.67.0.2.1");
    let g = Ground::over(fake);
    let c = g.composer();
    let ty = json!({"addrs": ["1.1.0.1.0.1.0.3.13"]});
    let frame = json!({
        "op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64",
        "runs": [run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 3)],
        "links": [
            {"home": "1.0.1.0.66", "from": {"spans": [{"start": "1.0.1.0.66.0.1.1", "width": "2"}]}, "to": {"addrs": []}, "ty": ty},
            {"home": "member", "from": {"member": [{"ordinal": "1", "width": "3"}]}, "to": {"addrs": ["member", "1.0.1.0.65"]}, "ty": ty, "old": "1.0.1.0.68.0.2.1"},
        ],
        "retract": ["1.0.1.0.67.0.2.1", "1.0.1.0.65.0.2.1"],
        "read_with": ["1.0.1.0.65"],
    });
    let (term, body) = c.doc_term_and_body(CheckedKind::Publish, &frame).unwrap();
    assert_eq!(term.as_doc_term(), DocTerm::One(&parse_address("1.0.1.0.1").unwrap()));
    let a = |text: &str| parse_address(text).unwrap();
    let (ty_unit, three, four, five_target, three_target) =
        (unit_span(&a("1.1.0.1.0.1.0.3.13")), unit_span(&a("1.0.1.0.65")), unit_span(&a("1.0.1.0.66")), unit_span(&a("1.0.1.0.67.0.2.1")), unit_span(&a("1.0.1.0.65.0.2.1")));
    let (retraction_ty, read_with_ty, trunk) = (unit_span(&a(T_RETRACTION)), unit_span(&a(T_READ_WITH)), unit_span(&a("1.0.1.0.1")));
    let four_span = extent_span("1.0.1.0.66.0.1.1", 2).unwrap();
    fn stored<'a>(elements: Vec<SlotElement<'a>>) -> DepositSlot<'a> {
        DepositSlot::Stored(elements)
    }
    let rows = [
        DepositRow {
            home: DepositHome::Member,
            kind: DepositKind::Copy,
            ty: stored(vec![SlotElement::Span(&ty_unit)]),
            from: DepositSlot::MemberPositions(vec![MemberPositions { ordinal: 1, width: 3 }]),
            to: stored(vec![SlotElement::Member, SlotElement::Span(&three)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.65")),
            kind: DepositKind::Retraction,
            ty: stored(vec![SlotElement::Span(&retraction_ty)]),
            from: stored(vec![SlotElement::Span(&three)]),
            to: stored(vec![SlotElement::Span(&three_target)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.65")),
            kind: DepositKind::ReadWith,
            ty: stored(vec![SlotElement::Span(&read_with_ty)]),
            from: stored(vec![SlotElement::Span(&trunk)]),
            to: stored(vec![SlotElement::Span(&three)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.66")),
            kind: DepositKind::Copy,
            ty: stored(vec![SlotElement::Span(&ty_unit)]),
            from: stored(vec![SlotElement::Span(&four_span)]),
            to: stored(vec![]),
        },
    ];
    let _ = (&four, &five_target);
    let shot = entry_body_publish([ShotSegmentPiece::Value(b"a"), ShotSegmentPiece::Value(b"b"), ShotSegmentPiece::Value(b"c")], None);
    assert_eq!(body.as_bytes(), entry_body_publication(shot, &rows).as_bytes(), "the rows in the signed order, the standing retraction skipped");
    let reads = g.fake.dialed();
    assert_eq!(reads.iter().filter(|op| *op == "find_links_ftt").count(), 3, "two retract skips and one read-with skip read: {reads:?}");
    // The mint form: the account as the term, the claim's row in the edition.
    let mint = json!({"op": "publish", "account": "1.0.1", "mint": true, "claim": true, "draft": "1.0.1.0.64", "runs": [run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 3)], "read_with": ["1.0.1.0.65"]});
    let (term, body) = c.doc_term_and_body(CheckedKind::Publish, &mint).unwrap();
    assert_eq!(term.as_doc_term(), DocTerm::One(&a("1.0.1")));
    let (edition_ty, draft) = (unit_span(&a(T_EDITION)), unit_span(&a("1.0.1.0.64")));
    let rows = [
        DepositRow {
            home: DepositHome::Edition,
            kind: DepositKind::EditionClaim,
            ty: stored(vec![SlotElement::Span(&edition_ty)]),
            from: stored(vec![SlotElement::Edition]),
            to: stored(vec![SlotElement::Span(&draft)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.65")),
            kind: DepositKind::ReadWith,
            ty: stored(vec![SlotElement::Span(&read_with_ty)]),
            from: stored(vec![SlotElement::Edition]),
            to: stored(vec![SlotElement::Span(&three)]),
        },
    ];
    let shot = entry_body_publish([ShotSegmentPiece::Value(b"a"), ShotSegmentPiece::Value(b"b"), ShotSegmentPiece::Value(b"c")], None);
    assert_eq!(body.as_bytes(), entry_body_publication(shot, &rows).as_bytes(), "the claim first in the edition, the read-with from the edition by tag");
    // The document form with the claim (skep #692): the term `doc`'s trunk;
    // the claim row first in `doc`'s own group — homed by address, `from`
    // the edition's unit span, never the tag — ahead of the read-with homed
    // in a later address; nothing read of the edition's members.
    let claimed = json!({"op": "publish", "doc": "1.0.1.0.1", "claim": true, "draft": "1.0.1.0.64", "runs": [run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 3)], "read_with": ["1.0.1.0.65"]});
    let (term, body) = c.doc_term_and_body(CheckedKind::Publish, &claimed).unwrap();
    assert_eq!(term.as_doc_term(), DocTerm::One(&a("1.0.1.0.1")));
    let edition = unit_span(&a("1.0.1.0.1"));
    let rows = [
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.1")),
            kind: DepositKind::EditionClaim,
            ty: stored(vec![SlotElement::Span(&edition_ty)]),
            from: stored(vec![SlotElement::Span(&edition)]),
            to: stored(vec![SlotElement::Span(&draft)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.65")),
            kind: DepositKind::ReadWith,
            ty: stored(vec![SlotElement::Span(&read_with_ty)]),
            from: stored(vec![SlotElement::Span(&edition)]),
            to: stored(vec![SlotElement::Span(&three)]),
        },
    ];
    let shot = entry_body_publish([ShotSegmentPiece::Value(b"a"), ShotSegmentPiece::Value(b"b"), ShotSegmentPiece::Value(b"c")], None);
    assert_eq!(body.as_bytes(), entry_body_publication(shot, &rows).as_bytes(), "the claim first in doc's group, by address; the read-with from the edition's unit span");
}

/// THE SUPERSESSION CLAIMS' GROUPS (the merge bridge lane): a `publish`
/// naming two daughters in `supersede` composes one group per daughter,
/// last in the trunk's group in declared order — the trunk by address, the
/// supersedes class's unit span, `from` the daughter's unit span, `to` the
/// tag `member` — exactly the group the client's own builder spells for the
/// same request (`skep_client::publication::Request::rows`), byte for byte
/// through the one builder; a daughter an ACTIVE claim of the session's
/// account's own already names, read off `in_claims` and its home's owner,
/// is skipped as the board's plan skips it, while another account's claim
/// skips nothing; at the mint form the group is homed under the edition's
/// tag, the entry the board's to refuse. One `in_claims` per daughter, one
/// `effective_owner` per claim's home.
#[test]
fn a_publications_supersede_entries_spell_the_claims_group_and_an_own_claim_is_skipped() {
    let mut fake = Fake::default().text("1.0.1.0.64", "1.0.1.0.64.0.1", 1, "abc");
    fake.claims.push(("1.0.1.0.1.1.2", "1.0.1.0.68"));
    fake.claims.push(("1.0.1.0.1.1.3", "1.0.2.0.1"));
    let g = Ground::over(fake);
    let c = g.composer();
    let frame = json!({
        "op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64",
        "runs": [run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 3)],
        "read_with": ["1.0.1.0.65"],
        "supersede": ["1.0.1.0.1.1.1", "1.0.1.0.1.1.2", "1.0.1.0.1.1.3"],
    });
    let (term, body) = c.doc_term_and_body(CheckedKind::Publish, &frame).unwrap();
    let a = |text: &str| parse_address(text).unwrap();
    assert_eq!(term.as_doc_term(), DocTerm::One(&a("1.0.1.0.1")));
    fn stored<'a>(elements: Vec<SlotElement<'a>>) -> DepositSlot<'a> {
        DepositSlot::Stored(elements)
    }
    let (sup_ty, read_with_ty, trunk, three) = (unit_span(&a(T_SUPERSEDES)), unit_span(&a(T_READ_WITH)), unit_span(&a("1.0.1.0.1")), unit_span(&a("1.0.1.0.65")));
    let (first, third) = (unit_span(&a("1.0.1.0.1.1.1")), unit_span(&a("1.0.1.0.1.1.3")));
    /// The group as the client's builder spells it: the trunk by address,
    /// the supersedes class, `from` the daughter, `to` the tag `member`.
    fn claim_group<'a>(trunk: &'a Address, sup_ty: &'a Span, daughter: &'a Span) -> DepositRow<'a> {
        DepositRow { home: DepositHome::Address(trunk), kind: DepositKind::Supersede, ty: DepositSlot::Stored(vec![SlotElement::Span(sup_ty)]), from: DepositSlot::Stored(vec![SlotElement::Span(daughter)]), to: DepositSlot::Stored(vec![SlotElement::Member]) }
    }
    let trunk_addr = a("1.0.1.0.1");
    let rows = [
        claim_group(&trunk_addr, &sup_ty, &first),
        claim_group(&trunk_addr, &sup_ty, &third),
        DepositRow { home: DepositHome::Address(&a("1.0.1.0.65")), kind: DepositKind::ReadWith, ty: stored(vec![SlotElement::Span(&read_with_ty)]), from: stored(vec![SlotElement::Span(&trunk)]), to: stored(vec![SlotElement::Span(&three)]) },
    ];
    let shot = entry_body_publish([ShotSegmentPiece::Value(b"a"), ShotSegmentPiece::Value(b"b"), ShotSegmentPiece::Value(b"c")], None);
    assert_eq!(body.as_bytes(), entry_body_publication(shot, &rows).as_bytes(), "the trunk's group: one claim per daughter in declared order, the own-claimed second daughter skipped, another account's claim skipping nothing; then the read-with's home");
    let reads = g.fake.dialed();
    assert_eq!(reads.iter().filter(|op| *op == "in_claims").count(), 3, "one in_claims per daughter: {reads:?}");
    assert_eq!(reads.iter().filter(|op| *op == "effective_owner").count(), 2, "the two claims' homes: {reads:?}");
    // The mint form: no trunk stands, the group under the edition's tag.
    let mint = json!({"op": "publish", "account": "1.0.1", "mint": true, "draft": "1.0.1.0.64", "runs": [run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 3)], "supersede": ["1.0.1.0.1.1.1"]});
    let (term, body) = c.doc_term_and_body(CheckedKind::Publish, &mint).unwrap();
    assert_eq!(term.as_doc_term(), DocTerm::One(&a("1.0.1")));
    let rows = [DepositRow { home: DepositHome::Edition, kind: DepositKind::Supersede, ty: stored(vec![SlotElement::Span(&sup_ty)]), from: stored(vec![SlotElement::Span(&first)]), to: stored(vec![SlotElement::Member]) }];
    let shot = entry_body_publish([ShotSegmentPiece::Value(b"a"), ShotSegmentPiece::Value(b"b"), ShotSegmentPiece::Value(b"c")], None);
    assert_eq!(body.as_bytes(), entry_body_publication(shot, &rows).as_bytes(), "homed under the edition's tag so the frame signs");
}

/// THE CANONICAL MEMBER-POSITION END (the client lane's C2): a `links`
/// entry's end in the member-position form is asserted canonical before the
/// signing — the lowest positions holding each value, consecutive positions
/// merged (`tools.json`, `publish`) — and refused naming the entry where it
/// is not: a span from ordinal 0, one of no width, two adjacent (one span
/// merged), two overlapping, two out of order; a canonical end composes the
/// body as the signer's own builder spells it, byte for byte, so the
/// assertion changes no body (the mutant that signs a row of another
/// spelling signs a body the board never composes, and the deposit is
/// refused `attestation_invalid:signature` after the send).
#[test]
fn a_member_position_end_is_asserted_canonical_before_the_signing() {
    let g = Ground::over(Fake::default().text("1.0.1.0.64", "1.0.1.0.64.0.1", 1, "abcdef"));
    let c = g.composer();
    let ty = json!({"addrs": ["1.1.0.1.0.1.0.3.13"]});
    let frame = |member: Value| json!({"op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64", "runs": [run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 6)], "links": [{"home": "member", "from": {"member": member}, "to": {"addrs": []}, "ty": ty}]});
    let span = |ordinal: &str, width: &str| json!({"ordinal": ordinal, "width": width});
    for (member, why) in [
        (json!([span("0", "2")]), "starts before the member's first position"),
        (json!([span("1", "0")]), "holds no position"),
        (json!([span("1", "3"), span("4", "2")]), "adjacent"),
        (json!([span("1", "3"), span("2", "1")]), "overlaps or precedes"),
        (json!([span("4", "1"), span("1", "2")]), "overlaps or precedes"),
    ] {
        let err = c.doc_term_and_body(CheckedKind::Publish, &frame(member.clone())).err().unwrap_or_else(|| panic!("{member}: composed"));
        let text = err.to_string();
        assert!(text.contains("not canonical") && text.contains("links[].from") && text.contains(why), "{member}: {text}");
    }
    assert_eq!(g.fake.dialed().iter().filter(|op| *op == "find_links_ftt").count(), 0, "refused at the row, before the deposit reads");
    let (_, body) = c.doc_term_and_body(CheckedKind::Publish, &frame(json!([span("1", "3"), span("5", "2")]))).unwrap();
    let ty_unit = unit_span(&parse_address("1.1.0.1.0.1.0.3.13").unwrap());
    let rows = [DepositRow {
        home: DepositHome::Member,
        kind: DepositKind::Copy,
        ty: DepositSlot::Stored(vec![SlotElement::Span(&ty_unit)]),
        from: DepositSlot::MemberPositions(vec![MemberPositions { ordinal: 1, width: 3 }, MemberPositions { ordinal: 5, width: 2 }]),
        to: DepositSlot::Stored(vec![]),
    }];
    let shot = entry_body_publish(b"abcdef".iter().map(|b| ShotSegmentPiece::Value(std::slice::from_ref(b))), None);
    assert_eq!(body.as_bytes(), entry_body_publication(shot, &rows).as_bytes(), "a canonical end composes as the builder spells it: no byte changes");
}

/// THE DEATH SIGNAL at a read the composer makes is the session's end and
/// no refusal of its own: a V-spec slot's `image` and the first read of a
/// shot copying in its draft's words — the board's price of it — each
/// answer [`Unattested::Died`], stopped at that first read
/// (the mutant that reads the death as the composer's halt answers it
/// `attest_not_composed`, and the page is told the shell could not sign).
#[test]
fn a_death_signal_at_a_read_is_the_sessions_end() {
    let fake = Fake::default().text("1.0.1.0.64", "1.0.1.0.64.0.1", 1, "abc");
    fake.closed.store(true, Ordering::SeqCst);
    let g = Ground::over(fake);
    let c = g.composer();
    assert!(matches!(c.slot(&json!([vspec("1.0.1.0.64")]), "from"), Err(Unattested::Died)));
    let shot = json!({"op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.64", "runs": [run("1.0.1.0.64", "1.0.1.0.64.0.1.1", 2)]});
    assert!(matches!(c.publish_body(&shot, "1.0.1.0.1"), Err(Unattested::Died)));
    assert_eq!(g.fake.dialed(), ["image", "publish_cost"], "each stopped at its first read");
}

/// A BOARD's REFUSAL AT A READ the composer makes is the board's verdict,
/// carried verbatim (`Unattested`'s refusal; `Composer::read`): a V-spec
/// slot whose source the board does not hold answers the board's own
/// `doc_not_registered`, of the `refused` kind, stopped at that one read
/// (the mutant that routes a read's rejection through the composer's own
/// halt answers it `attest_not_composed`, and the page is told the shell
/// could not sign where the board said why).
#[test]
fn a_boards_refusal_at_a_read_is_its_verdict_verbatim() {
    let g = Ground::over(Fake::default());
    match g.composer().slot(&json!([vspec("1.0.1.0.69")]), "from") {
        Err(Unattested::Refused(r)) => assert_eq!((r.name(), r.to_value()["kind"].as_str()), ("doc_not_registered", Some("refused")), "{r}"),
        other => panic!("the board's verdict was not carried: {other:?}"),
    }
    assert_eq!(g.fake.dialed(), ["image"], "stopped at its one read");
}

/// THE COMPOSER's PRECONDITION is its caller's — discharged by
/// `SessionEntry::attest` through `wants_attest` — so a frame outside the
/// eleven kinds reaching `attach` is a bug of this crate's, stopped loudly and
/// never answered as attached.
#[test]
#[should_panic(expected = "wants_attest")]
fn attach_stops_a_frame_past_its_precondition() {
    let g = Ground::over(Fake::default());
    let _ = g.composer().attach(&mut json!({"op": "delete", "doc": "1.0.1.0.1"}));
}

/// THE COMPOSER's PRECONDITION's other half: an `attest` already riding a
/// frame of the eleven kinds is the page's, the board's to judge, so a frame
/// carrying one reaching `attach` is stopped as loudly — never signed over
/// (the mutant that drops the precondition's check composes and replaces
/// the page's attest with the shell's).
#[test]
#[should_panic(expected = "wants_attest")]
fn attach_stops_a_frame_whose_attest_rides_already() {
    let g = Ground::over(Fake::default());
    let _ = g.composer().attach(&mut json!({"op": "insert", "doc": "1.0.1.0.1", "values": ["a"], "attest": {"alg": "x", "sig": "00"}}));
}

/// A signer that keeps every payload it is handed, beside the key it signs
/// with: what a composer signed, byte for byte.
struct Recording {
    key: Box<dyn Signer>,
    signed: Mutex<Vec<Vec<u8>>>,
}

impl Recording {
    fn over(key: Box<dyn Signer>) -> Recording {
        Recording { key, signed: Mutex::new(Vec::new()) }
    }

    /// The payloads signed since the last take, in order.
    fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.signed.lock().unwrap())
    }
}

impl Signer for Recording {
    fn public_key(&self) -> &skep_identity::PublicKey {
        self.key.public_key()
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.signed.lock().unwrap().push(payload.to_vec());
        self.key.sign(payload)
    }
}

/// THE WELL-KNOWN CREATION's CELL (wire.md §Credential refusals; the
/// eleventh kind): the composer signs a `create_well_known_document` over
/// the empty body under the op's own token, the frame's `doc` THE SLOT
/// DOCUMENT's OWN ADDRESS, `<account>.0.<slot>` — at every slot, the
/// mailbox's among them, where the board drops the attest unread — reading
/// nothing from the board. The bytes are the ones the frame's own builder
/// spells, never the frame over the parent account, never another slot's,
/// and never under `create_new_document`'s token; and they are the very
/// bytes `skep-client`'s composer signs for the same request, so the two
/// frames are one, `attest` and all (one frame, two composers). A frame
/// with no `slot`, or a `slot` no well-known document has, is one the board
/// refuses at its parse: the composer halts on it and nothing is signed.
#[test]
fn a_well_known_creation_is_signed_over_its_slots_own_address_as_the_client_signs_it() {
    use skep_client::address::{well_known_of, MAILBOX_SLOT, WELL_KNOWN_SLOTS};

    let g = Ground::over(Fake::default());
    let key = Recording::over(Box::new(signer_from_seed(&[7; 32])));
    let board_term = BoardTerm { log_position: 1, chain: [0xab; 32] };
    let composer = Composer { board: &g.board, token: &g.token, signer: &key, account: "1.0.1", board_term };
    let alg = key.public_key().alg().to_string();
    let own = parse_address("1.0.1").unwrap();
    // The creation is the owner's of ITS OWN account here, and of another it
    // names: the frame's `account` member is the session's, its `doc` the
    // named account's slot.
    for named in ["1.0.1", "1.0.1.4"] {
        let spelled = |doc: &str, op: ContentFreeOp| {
            entry_frame(&alg, board_term, &own, DocTerm::One(&parse_address(doc).unwrap()), &entry_body_empty(op))
        };
        for slot in WELL_KNOWN_SLOTS {
            let mut frame = json!({"op": "create_well_known_document", "account": named, "slot": slot});
            assert!(wants_attest(&frame), "slot {slot}: the shell attests every slot");
            composer.attach(&mut frame).unwrap();
            let signed = key.take();
            let document = well_known_of(named, slot);
            assert_eq!(signed, [spelled(&document, ContentFreeOp::CreateWellKnownDocument)], "slot {slot} of {named}: the empty body, the op's own token, over {document}");
            assert_ne!(signed[0], spelled(named, ContentFreeOp::CreateWellKnownDocument), "slot {slot}: never the parent account");
            assert_ne!(signed[0], spelled(&document, ContentFreeOp::CreateNewDocument), "slot {slot}: never `create_new_document`'s token");
            for other in WELL_KNOWN_SLOTS.into_iter().filter(|other| *other != slot) {
                assert_ne!(signed[0], spelled(&well_known_of(named, other), ContentFreeOp::CreateWellKnownDocument), "slot {slot}: never slot {other}'s frame");
            }
            assert_eq!(frame["attest"]["alg"], alg.as_str());
            // The client's composer, over the same request: the same bytes
            // signed, and the same frame. It composes the three published
            // slots' frames; the mailbox's it sends unsigned.
            if slot == MAILBOX_SLOT {
                assert!(skep_client::ceremony::well_known_frame(board_term, "1.0.1", named, slot, &key, None).is_err(), "the client signs no mailbox");
                assert!(key.take().is_empty());
                continue;
            }
            let clients = skep_client::ceremony::well_known_frame(board_term, "1.0.1", named, slot, &key, None).unwrap();
            assert_eq!(key.take(), signed, "slot {slot} of {named}: the client's composer signs the same bytes");
            assert_eq!(clients, frame, "slot {slot} of {named}: one frame, two composers");
        }
    }
    assert!(g.fake.dialed().is_empty(), "the creation's frame is composed from the request alone: {:?}", g.fake.dialed());

    // A frame the board refuses at its parse is one the composer halts on.
    for refused in [
        json!({"op": "create_well_known_document", "account": "1.0.1"}),
        json!({"op": "create_well_known_document", "account": "1.0.1", "slot": 6}),
        json!({"op": "create_well_known_document", "account": "1.0.1", "slot": 1}),
        json!({"op": "create_well_known_document", "account": "1.0.1", "slot": 64}),
        json!({"op": "create_well_known_document", "account": "1.0.1", "slot": "5"}),
        json!({"op": "create_well_known_document", "slot": 5}),
        json!({"op": "create_well_known_document", "account": "1.x", "slot": 5}),
    ] {
        let mut frame = refused.clone();
        let halt = composer.attach(&mut frame).expect_err("a frame the composer cannot make");
        assert!(matches!(halt, Unattested::Refused(_)), "{refused}: {halt}");
        assert_eq!(frame, refused, "{refused}: nothing is attached");
        assert!(key.take().is_empty(), "{refused}: nothing is signed");
    }
}
