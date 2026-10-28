//! THE COMPOSER's FENCE: the spelling it reads a frame in — the trunk, a
//! V-spec, an I-address's split, an I-range made where its reach is
//! spellable, a tumbler and an address within their component budget, the
//! wire's value faults faced as its own halt — and THE
//! BOARD's BUDGETS it keeps: each pinned to the board's own where the board
//! exports it, and each held before the work it bounds, against a fake board
//! that counts the reads the composer makes — a list past the wire's, a slot
//! past its spans, a shot past its re-insert budget or its body, an origin
//! past one delivery, an `image` that maps more than its extent — and, the
//! positive control beside them, a shot's body composed from the values it
//! copies in, run for run, as the signer's own builder spells it. And THE
//! COMPOSER's CONTRACT: a death signal at one of its reads the session's
//! end, and a board's refusal of one its verdict verbatim, never the
//! composer's own refusal; a frame past its precondition stopped loudly.

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
    assert_eq!(trunk_text("1.0.1.0.7.3.1").as_deref(), Some("1.0.1.0.7"));
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
/// component; the ten kinds are the checked set, each named by its own
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
    assert_eq!(CheckedKind::ALL.map(CheckedKind::as_str), ["create_new_document", "fork", "version", "insert", "publish", "make_link", "emit", "nullify", "assert_sup", "edit_link"]);
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
    let range = IRange::new("1.0.1.0.2.0.1", 1, 3).expect("a spellable range");
    assert_eq!((range.positions().collect::<Vec<_>>(), range.width()), (vec![1, 2, 3], 3));
    assert_eq!(IRange::new("1.0.1.0.2.0.1", u64::MAX - 2, 2).map(IRange::width), Some(2), "a reach at u64::MAX is spellable");
    assert!(IRange::new("1.0.1.0.2.0.1", u64::MAX, 1).is_none(), "a reach past it is none");
    let image = json!({"i_start": "1.0.1.0.2.0.1.18446744073709551615", "width": "1"});
    assert!(image_run(&image, "1.0.1.0.2").unwrap_err().to_string().contains("is no I-extent"), "an `image` run whose reach passes it is refused");
}

/// THE BOARD's BUDGETS the board exports are the shell's: the frame cap the
/// daemon's transport refuses a longer `/op` body by, M7's per-slot span
/// budget and M5's re-insert budget. The codec's own three — a wire list, an
/// insert's values, a tumbler's components — are private to the daemon, and
/// pinned by its behaviour in the shell's suite.
#[test]
fn the_budgets_are_the_boards() {
    assert_eq!(MAX_FRAME_BYTES, skepd::body_cap("POST", "/op"));
    assert_eq!(MAX_SLOT_SPANS, skep_links::MAX_SLOT_SPANS);
    assert_eq!(MAX_REINSERTED_VALUES, skep_arrangement::MAX_REINSERTED_VALUES as u64);
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
/// signal on every answer — and every op dialed, recorded by its name.
#[derive(Default)]
struct Fake {
    origins: HashMap<&'static str, Stored>,
    extents: HashMap<&'static str, u64>,
    images: HashMap<&'static str, Value>,
    /// The links a retraction tuple stands for: `find_links_ftt` over the
    /// retraction class and one of these as `to` answers one hit.
    retracted: Vec<&'static str>,
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

/// A SLOT is held to the wire's list before its first read — a V-spec list or
/// an address list one past [`MAX_WIRE_LIST`] refused with no op dialed, one
/// at it composed — and to [`MAX_SLOT_SPANS`] as it resolves: a source whose
/// `image` answers one span past the budget refused at the first read, one
/// at it composed (the mutants that drop either check compose a slot the
/// store refuses, after reads the frame should never have cost).
#[test]
fn a_slot_is_held_to_the_wire_list_and_its_span_budget() {
    let mut fake = Fake::default();
    fake.images.insert("1.0.1.0.8", image_runs(MAX_SLOT_SPANS + 1));
    fake.images.insert("1.0.1.0.9", image_runs(MAX_SLOT_SPANS));
    let g = Ground::over(fake);
    let c = g.composer();
    let past = Value::Array(vec![vspec("1.0.1.0.9"); MAX_WIRE_LIST + 1]);
    assert!(c.slot(&past, "from").is_err());
    assert!(c.slot(&json!({"resolve": past}), "successor.ty").is_err());
    assert!(c.slot(&json!({"addrs": vec!["1.0.1.0.1"; MAX_WIRE_LIST + 1]}), "to").is_err());
    assert!(g.fake.dialed().is_empty(), "nothing is read for a list past the wire's: {:?}", g.fake.dialed());
    assert_eq!(c.slot(&json!({"addrs": vec!["1.0.1.0.1"; MAX_WIRE_LIST]}), "to").unwrap().len(), MAX_WIRE_LIST);
    let refused = c.slot(&json!([vspec("1.0.1.0.8"), vspec("1.0.1.0.9")]), "from").unwrap_err();
    assert!(refused.to_string().contains("spans"), "{refused}");
    assert_eq!(g.fake.dialed(), ["image"], "refused at the first read past the budget");
    assert_eq!(c.slot(&json!([vspec("1.0.1.0.9")]), "from").unwrap().len(), MAX_SLOT_SPANS);
}

/// A run copied in from `origin` at `i_start`, `width` wide.
fn run(origin: &str, i_start: &str, width: u64) -> Value {
    json!({"origin": origin, "i_start": i_start, "width": width.to_string()})
}

/// A SHOT is held to its ARITHMETIC before any read: runs past the wire's
/// list, the staging draft's DISTINCT positions past the store's re-insert
/// budget (two disjoint runs past it together; the store mints each draft
/// identity once per shot, so a run named twice counts once), the copied
/// positions past what a body under the budget can carry, and a count past
/// `be64` (a window of width 2^64 − 1 and a run after it — a panic in the
/// signer's own builder) are each refused with nothing read; a draft at the
/// re-insert budget passes it, named once or twice over, and is read.
#[test]
fn a_shot_is_held_to_its_arithmetic_before_any_read() {
    let g = Ground::over(Fake::default());
    let c = g.composer();
    let shot = |runs: Vec<Value>| json!({"op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.2", "runs": runs});
    let draft_run = |width: u64| run("1.0.1.0.2", "1.0.1.0.2.0.1.1", width);
    let past_the_draft = run("1.0.1.0.2", &format!("1.0.1.0.2.0.1.{}", MAX_REINSERTED_VALUES + 1), 1);
    let cells = [
        ("runs past the wire's list", shot(vec![draft_run(1); MAX_WIRE_LIST + 1]), "elements"),
        ("the draft past the re-insert budget", shot(vec![draft_run(MAX_REINSERTED_VALUES), past_the_draft]), "re-inserts"),
        ("the copied positions past a body", shot(vec![run("1.0.1.0.1.1", "1.0.1.0.1.1.0.1.1", MAX_COPIED_POSITIONS + 1)]), "copies in"),
        ("a count past be64", shot(vec![run("1.0.9.0.1", "1.0.9.0.1.0.1.1", u64::MAX), run("1.0.9.0.1", "1.0.9.0.1.0.1.1", 1)]), "2^64"),
    ];
    for (cell, frame, says) in cells {
        let refused = c.publish_body(&frame, "1.0.1.0.1").unwrap_err();
        assert!(refused.to_string().contains(says), "{cell}: {refused}");
        assert!(g.fake.dialed().is_empty(), "{cell}: nothing is read: {:?}", g.fake.dialed());
    }
    for (cell, runs) in [
        ("the draft at the budget", vec![draft_run(MAX_REINSERTED_VALUES)]),
        ("the draft at the budget, named twice — the distinct count", vec![draft_run(MAX_REINSERTED_VALUES), draft_run(1)]),
    ] {
        let refused = c.publish_body(&shot(runs), "1.0.1.0.1").unwrap_err();
        assert!(!refused.to_string().contains("re-inserts"), "{cell} passes it: {refused}");
        assert_eq!(g.fake.dialed(), ["retrieve_doc_v_span_set"], "{cell}: and is read");
        g.fake.dialed.lock().unwrap().clear();
    }
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
    let mut fake = Fake::default().text("1.0.1.0.2", "1.0.1.0.2.0.1", 1, "abc").text("1.0.1.0.3", "1.0.1.0.3.0.1", 1, "xyz");
    fake.extents.insert("1.0.1.0.4", MAX_ANSWER_BYTES as u64 + 1);
    fake.images.insert("1.0.1.0.3", json!([{"i_start": "1.0.1.0.3.0.1.1", "width": "1000000"}]));
    let g = Ground::over(fake);
    let c = g.composer();
    let read = |origin: &'static str, spent: &mut usize| {
        let mut wanted = Wanted::new(origin);
        wanted.want(IRange::new(if origin == "1.0.1.0.3" { "1.0.1.0.3.0.1" } else { "1.0.1.0.2.0.1" }, 1, 3).expect("a spellable range"));
        c.read_back(wanted, spent)
    };
    assert!(read("1.0.1.0.4", &mut 0).unwrap_err().to_string().contains("more than one delivery"));
    assert_eq!(g.fake.dialed(), ["retrieve_doc_v_span_set"], "no image asked past the answer cap");
    g.fake.dialed.lock().unwrap().clear();
    assert!(read("1.0.1.0.3", &mut 0).unwrap_err().to_string().contains("maps more positions"));
    assert_eq!(g.fake.dialed(), ["retrieve_doc_v_span_set", "image"], "no values asked past the map");
    let mut spent = MAX_FRAME_BYTES - 2 * (4 + 1) - 1;
    assert!(read("1.0.1.0.2", &mut spent).is_err(), "the third value passes the body budget");
    let mut spent = 0;
    let read_back = read("1.0.1.0.2", &mut spent).unwrap();
    assert_eq!((read_back.value("1.0.1.0.2.0.1", 2), spent), (Some(&b"b"[..]), 3 * (4 + 1)));
}

/// THE SHOT's BODY, the positive control: runs copied in from the staging
/// draft and from a member of the shot's own trunk — the draft's twice,
/// overlapping — a window onto another document, and a base, composed from
/// the values each origin's own arrangement holds, read once per origin,
/// exactly as the signer's builder spells the same pieces.
#[test]
fn a_shots_body_is_composed_from_the_values_it_copies_in() {
    let fake = Fake::default().text("1.0.1.0.2", "1.0.1.0.2.0.1", 1, "abcd").text("1.0.1.0.1.1", "1.0.1.0.1.1.0.1", 1, "xyz");
    let g = Ground::over(fake);
    let frame = json!({
        "op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.2", "base": "1.0.1.0.1.1", "base_extent": "3",
        "runs": [
            run("1.0.1.0.2", "1.0.1.0.2.0.1.3", 2),
            run("1.0.9.0.1", "1.0.9.0.1.0.1.5", 3),
            run("1.0.1.0.1.1", "1.0.1.0.1.1.0.1.1", 2),
            run("1.0.1.0.2", "1.0.1.0.2.0.1.1", 3),
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
/// `to` the draft; `claim` without `mint` is the composer's halt.
#[test]
fn a_publications_deposit_rows_follow_the_signed_order_and_a_standing_retraction_is_skipped() {
    let mut fake = Fake::default().text("1.0.1.0.2", "1.0.1.0.2.0.1", 1, "abc");
    fake.retracted.push("1.0.1.0.5.0.2.1");
    let g = Ground::over(fake);
    let c = g.composer();
    let ty = json!({"addrs": ["1.1.0.1.0.1.0.3.13"]});
    let frame = json!({
        "op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.2",
        "runs": [run("1.0.1.0.2", "1.0.1.0.2.0.1.1", 3)],
        "links": [
            {"home": "1.0.1.0.4", "from": {"spans": [{"start": "1.0.1.0.4.0.1.1", "width": "2"}]}, "to": {"addrs": []}, "ty": ty},
            {"home": "member", "from": {"member": [{"ordinal": "1", "width": "3"}]}, "to": {"addrs": ["member", "1.0.1.0.3"]}, "ty": ty, "old": "1.0.1.0.6.0.2.1"},
        ],
        "retract": ["1.0.1.0.5.0.2.1", "1.0.1.0.3.0.2.1"],
        "read_with": ["1.0.1.0.3"],
    });
    let (term, body) = c.doc_term_and_body(CheckedKind::Publish, &frame).unwrap();
    assert_eq!(term.as_doc_term(), DocTerm::One(&parse_address("1.0.1.0.1").unwrap()));
    let a = |text: &str| parse_address(text).unwrap();
    let (ty_unit, three, four, five_target, three_target) =
        (unit_span(&a("1.1.0.1.0.1.0.3.13")), unit_span(&a("1.0.1.0.3")), unit_span(&a("1.0.1.0.4")), unit_span(&a("1.0.1.0.5.0.2.1")), unit_span(&a("1.0.1.0.3.0.2.1")));
    let (retraction_ty, read_with_ty, trunk) = (unit_span(&a(T_RETRACTION)), unit_span(&a(T_READ_WITH)), unit_span(&a("1.0.1.0.1")));
    let four_span = extent_span("1.0.1.0.4.0.1.1", 2).unwrap();
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
            home: DepositHome::Address(&a("1.0.1.0.3")),
            kind: DepositKind::Retraction,
            ty: stored(vec![SlotElement::Span(&retraction_ty)]),
            from: stored(vec![SlotElement::Span(&three)]),
            to: stored(vec![SlotElement::Span(&three_target)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.3")),
            kind: DepositKind::ReadWith,
            ty: stored(vec![SlotElement::Span(&read_with_ty)]),
            from: stored(vec![SlotElement::Span(&trunk)]),
            to: stored(vec![SlotElement::Span(&three)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.4")),
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
    let mint = json!({"op": "publish", "account": "1.0.1", "mint": true, "claim": true, "draft": "1.0.1.0.2", "runs": [run("1.0.1.0.2", "1.0.1.0.2.0.1.1", 3)], "read_with": ["1.0.1.0.3"]});
    let (term, body) = c.doc_term_and_body(CheckedKind::Publish, &mint).unwrap();
    assert_eq!(term.as_doc_term(), DocTerm::One(&a("1.0.1")));
    let (edition_ty, draft) = (unit_span(&a(T_EDITION)), unit_span(&a("1.0.1.0.2")));
    let rows = [
        DepositRow {
            home: DepositHome::Edition,
            kind: DepositKind::EditionClaim,
            ty: stored(vec![SlotElement::Span(&edition_ty)]),
            from: stored(vec![SlotElement::Edition]),
            to: stored(vec![SlotElement::Span(&draft)]),
        },
        DepositRow {
            home: DepositHome::Address(&a("1.0.1.0.3")),
            kind: DepositKind::ReadWith,
            ty: stored(vec![SlotElement::Span(&read_with_ty)]),
            from: stored(vec![SlotElement::Edition]),
            to: stored(vec![SlotElement::Span(&three)]),
        },
    ];
    let shot = entry_body_publish([ShotSegmentPiece::Value(b"a"), ShotSegmentPiece::Value(b"b"), ShotSegmentPiece::Value(b"c")], None);
    assert_eq!(body.as_bytes(), entry_body_publication(shot, &rows).as_bytes(), "the claim first in the edition, the read-with from the edition by tag");
    let bare_claim = json!({"op": "publish", "doc": "1.0.1.0.1", "claim": true, "draft": "1.0.1.0.2", "runs": []});
    assert!(c.doc_term_and_body(CheckedKind::Publish, &bare_claim).unwrap_err().to_string().contains("not admitted in this build"));
}

/// THE DEATH SIGNAL at a read the composer makes is the session's end and
/// no refusal of its own: a V-spec slot's `image` and a copied run's
/// read-back each answer [`Unattested::Died`], stopped at that first read
/// (the mutant that reads the death as the composer's halt answers it
/// `attest_not_composed`, and the page is told the shell could not sign).
#[test]
fn a_death_signal_at_a_read_is_the_sessions_end() {
    let fake = Fake::default().text("1.0.1.0.2", "1.0.1.0.2.0.1", 1, "abc");
    fake.closed.store(true, Ordering::SeqCst);
    let g = Ground::over(fake);
    let c = g.composer();
    assert!(matches!(c.slot(&json!([vspec("1.0.1.0.2")]), "from"), Err(Unattested::Died)));
    let shot = json!({"op": "publish", "doc": "1.0.1.0.1", "draft": "1.0.1.0.2", "runs": [run("1.0.1.0.2", "1.0.1.0.2.0.1.1", 2)]});
    assert!(matches!(c.publish_body(&shot, "1.0.1.0.1"), Err(Unattested::Died)));
    assert_eq!(g.fake.dialed(), ["image", "retrieve_doc_v_span_set"], "each stopped at its first read");
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
    match g.composer().slot(&json!([vspec("1.0.1.0.7")]), "from") {
        Err(Unattested::Refused(r)) => assert_eq!((r.name(), r.to_value()["kind"].as_str()), ("doc_not_registered", Some("refused")), "{r}"),
        other => panic!("the board's verdict was not carried: {other:?}"),
    }
    assert_eq!(g.fake.dialed(), ["image"], "stopped at its one read");
}

/// THE COMPOSER's PRECONDITION is its caller's — discharged by
/// `SessionEntry::attest` through `wants_attest` — so a frame outside the
/// ten kinds reaching `attach` is a bug of this crate's, stopped loudly and
/// never answered as attached.
#[test]
#[should_panic(expected = "wants_attest")]
fn attach_stops_a_frame_past_its_precondition() {
    let g = Ground::over(Fake::default());
    let _ = g.composer().attach(&mut json!({"op": "delete", "doc": "1.0.1.0.1"}));
}

/// THE COMPOSER's PRECONDITION's other half: an `attest` already riding a
/// frame of the ten kinds is the page's, the board's to judge, so a frame
/// carrying one reaching `attach` is stopped as loudly — never signed over
/// (the mutant that drops the precondition's check composes and replaces
/// the page's attest with the shell's).
#[test]
#[should_panic(expected = "wants_attest")]
fn attach_stops_a_frame_whose_attest_rides_already() {
    let g = Ground::over(Fake::default());
    let _ = g.composer().attach(&mut json!({"op": "insert", "doc": "1.0.1.0.1", "values": ["a"], "attest": {"alg": "x", "sig": "00"}}));
}
