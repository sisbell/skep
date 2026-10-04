use skep_identity::{entry_body_record, entry_frame, DocTerm, RecordRows};
use skep_registry::{encode, Binding};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::*;

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

/// The board term every record below is signed under.
const TERM: BoardTerm = BoardTerm { log_position: 1, chain: [7; 32] };

/// The genesis fingerprint every copy below names, and the hint it is
/// rebuilt under.
fn hint() -> RootHint {
    let genesis = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], genesis, None).unwrap()
}

/// A binding of `prefix` naming `to`, deposited in `home` and signed by
/// `signer` over the record frame the home's account composes under
/// [`TERM`].
fn signed_binding(signer: &HybridSigner, home: &Address, prefix: &str, to: &[Address]) -> String {
    let body = Body::Binding(Binding { prefix: prefix.into(), replaces: None });
    let sigless = encode(&body, None);
    let rows = RecordRows {
        ty: t_binding(),
        to,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: sigless.as_bytes(),
    };
    let account = account_of_document(home).expect("a doc 1's account");
    let frame = entry_frame(signer.public_key().alg(), TERM, &account, DocTerm::One(home), &entry_body_record(rows));
    encode(&body, Some(&signer.sign(&frame).iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// A stored link at `at`, homed in `home`, typed `ty`, from `from` to `to`.
fn stored(at: u64, address: &str, home: &Address, ty: &Address, from: &str, to: &[Address]) -> StoredLink {
    StoredLink { at, address: a(address), home: home.clone(), ty: Some(ty.clone()), from: vec![a(from)], to: to.to_vec() }
}

/// `signer`'s table, the one key it holds, as `account`'s before any act.
fn table(account: &str, signer: &HybridSigner) -> KeysAsOf {
    KeysAsOf { account: a(account), epoch: Epoch(0), at: 0, enrolled: vec![Enrolled { key: signer.public_key().clone(), anchor: true }] }
}

/// A copy under `dir` — its header naming [`hint`]'s genesis fingerprint, a
/// `make_link` row at each `(at, link, home)` — and a fetch cache of
/// `lines`, rebuilt offline.
fn rebuilt(dir: &Path, rows: &[(u64, &str, &Address)], lines: &[Value]) -> Mirror {
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
    let rows: Vec<Value> = rows
        .iter()
        .map(|(at, link, home)| json!({ "row": { "at": at, "op": "make_link", "link": link, "docs": [home.to_string()] } }))
        .collect();
    let feed: String = std::iter::once(&header).chain(&rows).map(|line| format!("{line}\n")).collect();
    fs::write(dir.join(FEED_COPY), feed).expect("the feed copy");
    fs::write(dir.join(FETCH_CACHE), lines.iter().map(|line| format!("{line}\n")).collect::<String>()).expect("the cache");
    Mirror::rebuild_offline(&hint(), dir).expect("rebuilt")
}

/// THE BINDING-WRITING ACCOUNT (R5 (g); REG-2.8, REG-2.6): a binding-typed
/// record an org deposits in its own doc 1 — signed by the org's own key, so
/// the board's home check and the verify would both pass it — binds nothing:
/// it is counted apart, never judged, and its prefix has no standing; the
/// registrar's own binding, deposited the same way in the claimant's doc 1,
/// is SIGNED and stands. The copy is rebuilt offline, every fetch served
/// from a cache written by `Fetched`.
#[test]
fn a_binding_typed_record_outside_the_claimants_doc_one_binds_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registrar = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[1; 32]).expect("tag 1");
    let org = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[2; 32]).expect("tag 1");
    let bound = [a("1.0.2")];
    let (registry, own) = (a("1.0.1.0.1"), a("1.0.2.0.1"));
    let mut kept = Fetched::default();
    let lines: Vec<Value> = [
        kept.keep_link(stored(1, "1.0.1.0.1.0.2.1", &registry, &commons_type(&[3]), "1.0.1", &[])),
        kept.keep_link(stored(2, "1.0.2.0.1.0.2.1", &own, t_binding(), "1.0.2.0.1.0.1.1", &bound)),
        kept.keep_link(stored(3, "1.0.1.0.1.0.2.2", &registry, t_binding(), "1.0.1.0.1.0.1.1", &bound)),
        kept.keep_atom(a("1.0.2.0.1.0.1.1"), signed_binding(&org, &own, "1.9", &bound)),
        kept.keep_atom(a("1.0.1.0.1.0.1.1"), signed_binding(&registrar, &registry, "1.8", &bound)),
        kept.keep_board(TERM, &"07".repeat(32)),
        kept.keep_keys(table("1.0.1", &registrar)),
        kept.keep_keys(table("1.0.2", &org)),
    ]
    .into_iter()
    .map(|line| line.expect("a value not held writes its line"))
    .collect();
    let rows = [(1, "1.0.1.0.1.0.2.1", &registry), (2, "1.0.2.0.1.0.2.1", &own), (3, "1.0.1.0.1.0.2.2", &registry)];
    let mirror = rebuilt(dir.path(), &rows, &lines);
    let verdict = mirror.index().standing(&a("1.8")).map(|s| s.current.verdict);
    assert_eq!(verdict, Some(Verdict::Signed(Fingerprint::of(registrar.public_key()))), "the registrar's binding stands");
    assert_eq!(mirror.index().standing(&a("1.9")), None, "the org's binding-typed record binds nothing");
    assert_eq!(mirror.stats().binding_typed_outside_home, 1, "counted apart");
    assert!(mirror.index().suppressed().is_empty(), "and never judged: {:?}", mirror.index().suppressed());
}

/// AN ADDRESS PAST A MACHINE WORD IS AN ADDRESS (wire.md §Value encodings:
/// a component is one decimal natural, of any size), and what the canonical
/// rule admits is not judged again: the registrar's binding of a prefix one
/// component of which passes `u64`, its binding naming an account one
/// component of which does — the stored link's target read whole, so the
/// frame the verify rebuilds is the one the registrar signed — and its
/// binding of a prefix past the wire's digit cap, which a record's own cap
/// bounds instead, each stand SIGNED, and nothing is suppressed.
#[test]
fn a_record_naming_an_address_past_a_machine_word_stands_signed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registrar = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[1; 32]).expect("tag 1");
    let registry = a("1.0.1.0.1");
    let (word, wide_account) = ("1.18446744073709551616", a("1.0.18446744073709551616"));
    let past_the_wire = format!("1.{}", "9".repeat(4097));
    let (to_org, to_wide) = ([a("1.0.2")], [wide_account.clone()]);
    let mut kept = Fetched::default();
    let lines: Vec<Value> = [
        kept.keep_link(stored(1, "1.0.1.0.1.0.2.1", &registry, &commons_type(&[3]), "1.0.1", &[])),
        kept.keep_link(stored(2, "1.0.1.0.1.0.2.2", &registry, t_binding(), "1.0.1.0.1.0.1.1", &to_org)),
        kept.keep_link(stored(3, "1.0.1.0.1.0.2.3", &registry, t_binding(), "1.0.1.0.1.0.1.2", &to_wide)),
        kept.keep_link(stored(4, "1.0.1.0.1.0.2.4", &registry, t_binding(), "1.0.1.0.1.0.1.3", &to_org)),
        kept.keep_atom(a("1.0.1.0.1.0.1.1"), signed_binding(&registrar, &registry, word, &to_org)),
        kept.keep_atom(a("1.0.1.0.1.0.1.2"), signed_binding(&registrar, &registry, "1.8", &to_wide)),
        kept.keep_atom(a("1.0.1.0.1.0.1.3"), signed_binding(&registrar, &registry, &past_the_wire, &to_org)),
        kept.keep_board(TERM, &"07".repeat(32)),
        kept.keep_keys(table("1.0.1", &registrar)),
    ]
    .into_iter()
    .map(|line| line.expect("a value not held writes its line"))
    .collect();
    let rows = [
        (1, "1.0.1.0.1.0.2.1", &registry),
        (2, "1.0.1.0.1.0.2.2", &registry),
        (3, "1.0.1.0.1.0.2.3", &registry),
        (4, "1.0.1.0.1.0.2.4", &registry),
    ];
    let mirror = rebuilt(dir.path(), &rows, &lines);
    assert!(mirror.index().suppressed().is_empty(), "{:?}", mirror.index().suppressed());
    let signed = Verdict::Signed(Fingerprint::of(registrar.public_key()));
    let past_a_word = mirror.index().standing(&a(word)).expect("a prefix past a machine word");
    assert_eq!(past_a_word.current.verdict, signed);
    let naming = mirror.index().standing(&a("1.8")).expect("a binding naming an account past a machine word");
    assert_eq!((naming.current.verdict, naming.current.record.account), (signed.clone(), Some(wide_account)));
    let past_the_cap = mirror.index().standing(&record_address(&past_the_wire)).expect("a prefix past the wire's cap");
    assert_eq!(past_the_cap.current.verdict, signed);
}

/// The address arithmetic the fold rests on: a doc 1's account.
#[test]
fn the_homes_account_is_read_by_arithmetic() {
    assert_eq!(account_of_document(&a("1.0.1.0.1")), Some(a("1.0.1")));
    assert_eq!(account_of_document(&a("1.0.2.3.0.1")), Some(a("1.0.2.3")));
    assert_eq!(account_of_document(&a("1.0.1.0.1.2")), Some(a("1.0.1")), "a member's account");
    assert_eq!(account_of_document(&a("1.0.1.0.1.0.1.4")), Some(a("1.0.1")), "an element's");
    assert_eq!(account_of_document(&a("1.0.1")), None);
}

/// A link row is an unattested `make_link` with a link and a home — the
/// row a record deposit and a credential deposit alike commit; an
/// attested one and one naming no document are no link row, nothing the
/// fold takes. A `nullify` is read as the documents it names, and a
/// `publish` as the members it names.
#[test]
fn a_link_row_is_an_unattested_make_link() {
    let row = json!({ "at": 7, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": ["not an address", "1.0.2.0.1"] });
    let link = Row::Link { at: 7, link: a("1.0.2.0.1.0.2.1"), home: a("1.0.2.0.1") };
    assert_eq!(Row::of(&row), link, "the home is the first document that is an address");
    let mut attested = row.clone();
    attested["attest"] = json!({});
    assert_eq!(Row::of(&attested), Row::Other);
    assert_eq!(Row::of(&json!({ "at": 7, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": [] })), Row::Other);
    let nullify = json!({ "at": 8, "op": "nullify", "link": "1.0.2.0.1.0.2.1", "docs": ["1.0.2.0.1"] });
    assert_eq!(Row::of(&nullify), Row::Nullify { at: 8, docs: vec![a("1.0.2.0.1")] });
    let publish = json!({ "at": 9, "op": "publish", "docs": ["1.0.2.0.1.1"] });
    assert_eq!(Row::of(&publish), Row::Chain { members: vec![a("1.0.2.0.1.1")] });
}

/// THE FETCH CACHE'S FORMAT has one writer and one reader: every kind of
/// line `Fetched` keeps reads back into the value it kept; a value it
/// holds already — a credential table read again for another position
/// of its epoch among them — writes no second line, and another table
/// under the same epoch does; and a line one of whose members does not
/// read — a keys line's entry, a link line's address or its type — holds
/// nothing at all, never a smaller value.
#[test]
fn every_cache_line_reads_back_as_what_was_kept() {
    let key = |seed: u8| HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[seed; 32]).expect("tag 1").public_key().clone();
    let mut kept = Fetched::default();
    let link = StoredLink {
        at: 5,
        address: a("1.0.1.0.1.0.2.1"),
        home: a("1.0.1.0.1"),
        ty: Some(a("1.1.0.1.0.1.0.3.1")),
        from: vec![a("1.0.1.0.1.0.1.1")],
        to: vec![a("1.0.2")],
    };
    let keys = KeysAsOf {
        account: a("1.0.2"),
        epoch: Epoch(5),
        at: 9,
        enrolled: vec![Enrolled { key: key(3), anchor: true }, Enrolled { key: key(4), anchor: false }],
    };
    let atom = (a("1.0.1.0.1.0.1.1"), r#"{"type":"binding","prefix":"1.5"}"#.to_string());
    let (term, chain) = (BoardTerm { log_position: 12, chain: [7; 32] }, "07".repeat(32));
    let lines: Vec<Value> = [
        kept.keep_link(link.clone()),
        kept.keep_atom(atom.0.clone(), atom.1.clone()),
        kept.keep_keys(keys.clone()),
        kept.keep_retracted(14, a("1.0.2.0.1.0.2.1")),
        kept.keep_board(term, &chain),
        kept.keep_claim(3, a("1.0.1")),
    ]
    .into_iter()
    .map(|line| line.expect("a value not held writes its line"))
    .collect();
    let mut recalled = Fetched::default();
    for line in &lines {
        recalled.recall(&serde_json::from_str(&line.to_string()).expect("a line is JSON"));
    }
    assert_eq!(recalled, kept);
    let again = [
        kept.keep_link(link),
        kept.keep_atom(atom.0, atom.1),
        kept.keep_keys(KeysAsOf { at: 11, ..keys.clone() }),
        kept.keep_retracted(14, a("1.0.2.0.1.0.2.1")),
        kept.keep_board(term, &chain),
        kept.keep_claim(3, a("1.0.1")),
    ];
    assert!(again.iter().all(Option::is_none), "a value held already writes no line: {again:?}");
    assert_eq!(recalled, kept, "and holds what it held");
    let rotated = KeysAsOf { enrolled: vec![Enrolled { key: key(4), anchor: false }], ..keys };
    assert!(kept.keep_keys(rotated).is_some(), "another table under the epoch is a new line");
    let torn = |line: &Value, tear: &dyn Fn(&mut Value)| {
        let mut torn = line.clone();
        tear(&mut torn);
        let mut held = Fetched::default();
        held.recall(&torn);
        held
    };
    assert!(torn(&lines[2], &|l| l["keys"]["enrolled"][1]["alg"] = json!("no-such-alg")).keys.is_empty(), "a keys entry");
    assert!(torn(&lines[0], &|l| l["link"]["to"] = json!(["not an address"])).links.is_empty(), "a link's target");
    assert!(torn(&lines[0], &|l| l["link"]["from"] = json!(["1.0.1.0.1.0.1.1", 7])).links.is_empty(), "a link's atom");
    assert!(torn(&lines[0], &|l| l["link"]["ty"] = json!("not an address")).links.is_empty(), "a link's type");
}

/// A LINE CUT SHORT IS NEVER RUN INTO, AND HOLDS NOTHING: a held cache a
/// crash left mid-line is appended to on a line of its own, every byte of
/// it counted; and the cache's reader takes every line that reads and passes
/// over the one that does not, refusing nothing — the fold fetches afresh
/// what it held.
#[test]
fn a_line_cut_short_is_never_run_into_and_holds_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(FETCH_CACHE);
    let cut = r#"{"atom":{"addr"#;
    fs::write(&path, cut).expect("a cache a crash cut short");
    let mut lines = Lines::held(path.clone());
    let claim = json!({ "claim": { "at": 3, "claimant": "1.0.1" } });
    lines.append(&claim).expect("appended");
    let held = fs::read_to_string(&path).expect("the cache");
    assert_eq!(held, format!("{cut}\n{claim}\n"), "the cut line ended, the next on its own");
    assert_eq!(lines.bytes, held.len() as u64, "every byte counted");
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
    fs::write(dir.path().join(FEED_COPY), format!("{header}\n")).expect("the feed copy");
    let mirror = Mirror::rebuild_offline(&hint(), dir.path()).expect("a line that does not read refuses nothing");
    assert_eq!(mirror.fetched.claim, Some((3, a("1.0.1"))), "the line after it reads");
}
