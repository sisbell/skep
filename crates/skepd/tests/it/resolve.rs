//! THE VERIFYING RESOLVER AGAINST A LIVE BOARD — `skep-resolve` taken as a
//! library by this suite, where boards are spawned and registered: THE
//! REFERENCE CELL (the resolver's verdict on every row equals the daemon's
//! admission; rm-2, REG-1.86 (e)), the SUPPRESS of a body the daemon never
//! admitted and of one a seam tampered, THE COURIER VECTOR (REG-3.13; R5
//! (b)), THE ROOT MOVE's resume and its refusals (REG-3.18, REG-3.19,
//! REG-3.42), NO NEGATIVE CACHE (REG-3.10), THE CHAIN WALK's recovery of an
//! un-arranged atom (REG-3.25), the end-to-end walk from the hint (REG-3.7),
//! the recording of the resolver crate's own fixture, and THE MEASUREMENTS
//! (the registry seam investigation §3.1, §3.3, §3.4), reported and never
//! asserted.
//!
//! Every board here is the suite's own claimed board: its registrar is the
//! claimant, its console the claimant's signed session, its genesis set the
//! ceremony's two keys — so one realm id names every board the suite spawns,
//! and a board of another genesis is made by hand where a refusal needs one.

use crate::common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{canonical_record, Fingerprint};
use skep_registry::{encode, Body, BodyKind};
use skep_resolve::{
    guest_resolve, resolve, Board, Cause, Http, MemberOutcome, Method, Mirror, MirrorError,
    NameResolver, Opened, Origin, RealmId, Refusal, Resolution, RootHint, Term, Transport,
    TransportError, Transports, Unreachable, Verdict,
};
use skep_signature::Ed25519SigningKey as SigningKey;

/// The orgs' principals, above every other suite's ids; an org's key seed is
/// its own number.
const ORG_PRINCIPAL_BASE: u64 = 1_000;

fn addr(s: &str) -> Address {
    skep_resolve::parse_address(s).unwrap_or_else(|| panic!("{s} is an address"))
}

/// THE REALM every board this suite spawns belongs to, an unforked lineage's
/// and so its genesis fingerprint alone (REG-3.39, REG-3.40): the
/// fingerprint of the ceremony's genesis set, the paper anchor and the
/// notebook device key.
fn suite_realm() -> Fingerprint {
    RealmId::genesis_fingerprint(&[Fingerprint::of(&public_key_of(&anchor_key())), Fingerprint::of(&public_key_of(&device_key()))])
}

/// THE ROOT HINT for a board at `port` (REG-3.2): its loopback origin and
/// the suite's realm, no fork point.
fn hint_for(port: u16) -> RootHint {
    RootHint::new(vec![Origin::parse(&format!("http://127.0.0.1:{port}")).expect("canonical")], suite_realm(), None)
        .expect("one origin")
}

/// The registrar's console: the claimant's signed session (REG-4.108).
fn console(port: u16) -> String {
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key())
}

/// A deterministic key per org — bytes no other suite's seed carrier takes.
fn org_key(i: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed[8] = 0x5a;
    SigningKey::from_bytes(&seed)
}

/// One registered org: its node account on the registrar's board, keyed and
/// bound, its doc 1 minted, its endpoint where one was deposited.
struct Org {
    principal: u64,
    prefix: String,
    account: String,
    doc1: String,
    key: SigningKey,
    node_signed: String,
    binding: String,
    endpoint: Option<String>,
    extra_keys: Vec<SigningKey>,
}

/// Mint the node account's doc 1 published (REG-1.51).
fn mint_doc_one(port: u16, signed: &str, account: &str) -> String {
    acked_addr(&op(port, Some(signed), &create_frame(account, Some(true))))
}

/// A record atom inserted DECLARED under `ty` at `home`'s next position from
/// `signed`, then its `make_link` to `to` — both asserted.
fn land_and_link(port: u16, signed: &str, home: &str, ty: &str, to: &[&str], atom: &str) -> String {
    let ordinal = next_content_ordinal(port, Some(signed), home);
    let v = op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    );
    let atom_addr = acked_addr(&v);
    acked_addr(&op(port, Some(signed), &typed_link_frame(home, &[atom_addr.as_str()], to, ty)))
}

/// A KEY ACT of the org's own: one more device key enrolled into its doc 1
/// from its own signed session (AUTH-2.69's holder arm).
fn enroll_extra_key(port: u16, org: &Org, extra: &SigningKey) {
    let atom = signed_atom(port, &org.node_signed, &org.doc1, T_ENROLL, &[&org.account], &enroll_atom(&[extra]));
    land_and_link(port, &org.node_signed, &org.doc1, T_ENROLL, &[&org.account], &atom);
}

/// REGISTER one org as the registrar's console does (REG-1.1; the walk
/// `registry.rs` drives): the node account delegated, keyed by a hire into
/// the registrar's doc 1, bound at `prefix`, its doc 1 minted, its endpoint
/// deposited where `origins` names one, then `key_acts` further keys
/// enrolled.
fn register_org(port: u16, console: &str, i: u64, prefix: &str, origins: Option<&[&str]>, key_acts: usize) -> Org {
    let principal = ORG_PRINCIPAL_BASE + i;
    let key = org_key(principal);
    let (account, _bare) = bootstrap_delegate(port, principal);
    let node_signed = hire(port, console, CLAIMANT_DOC1, &account, principal, &key);
    let binding = deposit_binding(port, console, prefix, Some(&account), None);
    let doc1 = mint_doc_one(port, &node_signed, &account);
    let endpoint = origins.map(|o| deposit_endpoint(port, &node_signed, &doc1, o, None));
    let mut org = Org { principal, prefix: prefix.to_string(), account, doc1, key, node_signed, binding, endpoint, extra_keys: Vec::new() };
    for j in 0..key_acts {
        let extra = org_key(principal * 100 + j as u64 + 1);
        enroll_extra_key(port, &org, &extra);
        org.extra_keys.push(extra);
    }
    org
}

/// The table this resolver's own resolution of a name answers from — fixed,
/// so no test dials the network (REG-3.35: the term is met by an address and
/// never by a name; whose address is the resolver's own business).
struct Names(BTreeMap<&'static str, Vec<IpAddr>>);

impl NameResolver for Names {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(self.0.get(host).cloned().unwrap_or_default())
    }
}

fn names() -> Names {
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let mut t = BTreeMap::new();
    for host in [
        "acme.example", "acme.example.net", "stale.example", "four.example", "five.example", "six.example",
        "seven.example", "eleven.example", "thirteen.example", "fourteen.example", "moved.example",
        "org.example",
    ] {
        t.insert(host, vec![public]);
    }
    t.insert("loop.example", vec![loopback]);
    t.insert("dead.example", Vec::new());
    Names(t)
}

/// A cold mirror of the board at `port` under `dir`, through the shipped
/// dial.
fn cold_mirror(port: u16, dir: &Path) -> Mirror {
    Mirror::open(&hint_for(port), dir, &skep_resolve::dial_http).unwrap_or_else(|e| panic!("a cold mirror: {e}"))
}

fn resolve_prefix(mirror: &mut Mirror, prefix: &str) -> Resolution {
    resolve(mirror, &addr(prefix), &names(), &Transports::default()).unwrap_or_else(|e| panic!("resolve {prefix}: {e}"))
}

/// The dial member a BOUND face would take, as `(index, origin)`.
fn dial_of(r: &Resolution) -> Option<(usize, String)> {
    match r {
        Resolution::Bound { dial, .. } => Some((dial.member_index, dial.origin.as_str().to_string())),
        _ => None,
    }
}

// ── the seam: a transport that records, and may tamper ─────────────────────

/// How a recorded delivery is tampered on its way to the mirror (a seam in
/// THIS SUITE's transport and never in the daemon, which admits no such
/// record): a binding's `sig` zeroed at its width, or its body spaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tamper {
    ZeroSig,
    Space,
}

/// The HTTP transport with every exchange logged and the named bindings'
/// deliveries tampered.
struct Recording {
    inner: Http,
    log: Option<Rc<RefCell<Vec<Value>>>>,
    tamper: Rc<Vec<(String, Tamper)>>,
}

impl Transport for Recording {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let (status, mut response) = self.inner.exchange(method, path, body)?;
        if path == "/op" && status == 200 && !self.tamper.is_empty() {
            response = tamper_delivery(&response, &self.tamper);
        }
        if let Some(log) = &self.log {
            log.borrow_mut().push(json!({
                "method": method.as_str(),
                "path": path,
                "request": String::from_utf8_lossy(body),
                "status": status,
                "response": String::from_utf8_lossy(&response),
            }));
        }
        Ok((status, response))
    }
}

/// A delivery's binding atom at a tampered prefix, rewritten.
fn tamper_delivery(response: &[u8], tamper: &[(String, Tamper)]) -> Vec<u8> {
    let Ok(mut v) = serde_json::from_slice::<Value>(response) else { return response.to_vec() };
    if v["resp"].as_str() != Some("delivery") {
        return response.to_vec();
    }
    let Some(items) = v["items"].as_array_mut() else { return response.to_vec() };
    for item in items {
        let Some(text) = item["atom"].as_str().map(str::to_string) else { continue };
        let Ok(record) = skep_registry::parse(BodyKind::Binding, text.as_bytes()) else { continue };
        let Body::Binding(b) = &record.body else { continue };
        for (prefix, mode) in tamper {
            if b.prefix.to_string() == *prefix {
                let rewritten = match mode {
                    Tamper::ZeroSig => encode(&record.body, Some(&"0".repeat(record.sig.as_deref().map_or(0, str::len)))),
                    Tamper::Space => text.replacen(':', ": ", 1),
                };
                item["atom"] = Value::String(rewritten);
            }
        }
    }
    v.to_string().into_bytes()
}

/// A dial through [`Recording`]: logged where `log` is given, tampered where
/// `tamper` names a prefix.
fn recording_dial(
    log: Option<Rc<RefCell<Vec<Value>>>>,
    tamper: Vec<(String, Tamper)>,
) -> impl Fn(&Origin) -> Result<Box<dyn Transport>, TransportError> {
    let tamper = Rc::new(tamper);
    move |o: &Origin| -> Result<Box<dyn Transport>, TransportError> {
        Ok(Box::new(Recording { inner: Http::for_origin(o)?, log: log.clone(), tamper: tamper.clone() }))
    }
}

/// Copy a data directory whole — a root move's new address serves the same
/// journal (REG-3.18).
fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("mkdir");
    for entry in fs::read_dir(src).expect("read_dir") {
        let entry = entry.expect("entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).expect("copy");
        }
    }
}

// ── the fixture board, and its recording ───────────────────────────────────

/// The onion address the self-authenticating cells use.
const ONION: &str = "http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";

/// THE FIXTURE BOARD: fourteen orgs, each the producer of one face or one
/// arm of the replay matrix; the prefix each takes is its own number under
/// `1`.
fn fixture_board(port: u16) -> BTreeMap<String, Org> {
    let console = console(port);
    let mut orgs = BTreeMap::new();
    let mut keep = |o: Org| {
        orgs.insert(o.prefix.clone(), o);
    };
    // 1.2 — BOUND, with the endpoint's currency: e2 replaces e1 and is
    // current, e3 names e1 again and is inert (REG-1.10).
    let o2 = register_org(port, &console, 2, "1.2", Some(&["https://acme.example"]), 0);
    let e1 = o2.endpoint.clone().expect("deposited");
    let _e2 = deposit_endpoint(port, &o2.node_signed, &o2.doc1, &["https://acme.example.net"], Some(&e1));
    let _e3 = deposit_endpoint(port, &o2.node_signed, &o2.doc1, &["https://stale.example"], Some(&e1));
    keep(o2);
    // 1.3 — BOUND-BUT-UNREACHABLE: no endpoint deposit yet.
    keep(register_org(port, &console, 3, "1.3", None, 0));
    // 1.4 — tampered on record: its binding's `sig` zeroed, so the resolver
    // suppresses it (UNSIGNED) and answers UNREGISTERED.
    keep(register_org(port, &console, 4, "1.4", Some(&["https://four.example"]), 0));
    // 1.5 — RETIRED-WITH-HISTORY: a targetless binding replaces the allocation.
    let o5 = register_org(port, &console, 5, "1.5", Some(&["https://five.example"]), 0);
    deposit_binding(port, &console, "1.5", None, Some(&o5.binding));
    keep(o5);
    // 1.6 — THE REPLAY MATRIX: a double allocation (inert), a same-account
    // binding naming the stale state (inert), the restoration naming the
    // current state (honored).
    let o6 = register_org(port, &console, 6, "1.6", Some(&["https://six.example"]), 0);
    let (b6, _) = bootstrap_delegate(port, ORG_PRINCIPAL_BASE + 600);
    let inert = deposit_binding(port, &console, "1.6", Some(&b6), None);
    deposit_binding(port, &console, "1.6", Some(&o6.account), Some(&inert));
    deposit_binding(port, &console, "1.6", Some(&o6.account), Some(&o6.binding));
    keep(o6);
    // 1.7 — the org's own nullify (REG-1.11): e2 (plaintext) replaces e1,
    // then e2 is nullified and e1 stands current again.
    let o7 = register_org(port, &console, 7, "1.7", Some(&["https://seven.example"]), 0);
    let e7 = o7.endpoint.clone().expect("deposited");
    let e7_2 = deposit_endpoint(port, &o7.node_signed, &o7.doc1, &["http://plain.example"], Some(&e7));
    expect_resp(&op(port, Some(&o7.node_signed), &nullify_frame(&o7.doc1, &e7_2)), "ack_addr");
    keep(o7);
    // 1.8 — unreachable-by-policy on the SCHEME term (REG-3.34).
    keep(register_org(port, &console, 8, "1.8", Some(&["http://plain.example"]), 0));
    // 1.9 — unreachable-by-policy on the HOST term at a literal (REG-3.35).
    keep(register_org(port, &console, 9, "1.9", Some(&["https://127.0.0.1"]), 0));
    // 1.10 — THE DIAL NOT MADE: an onion member on a client with no onion
    // transport (RES-28).
    keep(register_org(port, &console, 10, "1.10", Some(&[ONION]), 0));
    // 1.11 — the one precedence: the onion is not dialed, the https member
    // after it is.
    keep(register_org(port, &console, 11, "1.11", Some(&[ONION, "https://eleven.example"]), 0));
    // 1.12 — the HOST term at a NAME this resolver resolves to a loopback.
    keep(register_org(port, &console, 12, "1.12", Some(&["https://loop.example"]), 0));
    // 1.13 — BOUND, an ordinary org.
    keep(register_org(port, &console, 13, "1.13", Some(&["https://thirteen.example"]), 0));
    // 1.14 — tampered on record: its binding's body spaced, no record under
    // the canonical rule (malformed), UNREGISTERED at the resolver.
    keep(register_org(port, &console, 14, "1.14", Some(&["https://fourteen.example"]), 0));
    // 1.15 — a dead origin: a name this resolver resolves to nothing.
    keep(register_org(port, &console, 15, "1.15", Some(&["https://dead.example"]), 0));
    // THE REGISTRAR'S ROTATION, last: a third key enrolled into the
    // claimant's doc 1 from the console, then the console's own device key
    // retired from the new key's session — so every binding above was signed
    // by a key the live table no longer holds, and verifies AS OF its
    // position alone (REG-1.86 (e); "never the live table").
    let k3 = rotated_registrar_key();
    let atom = signed_atom(port, &console, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &enroll_atom(&[&k3]));
    land_and_link(port, &console, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &atom);
    let k3_signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &k3);
    let retire = canonical_record(&[Fingerprint::of(&public_key_of(&device_key()))], None);
    let atom = signed_atom(port, &k3_signed, CLAIMANT_DOC1, T_RETIRE, &[CLAIMANT_ACCOUNT], &json_atom(&retire));
    land_and_link(port, &k3_signed, CLAIMANT_DOC1, T_RETIRE, &[CLAIMANT_ACCOUNT], &atom);
    orgs
}

/// The registrar's third key, enrolled at the fixture board's end.
fn rotated_registrar_key() -> SigningKey {
    distinct_key(63)
}

/// The prefixes the fixture's readers resolve, in the order the recording
/// resolves them.
const FIXTURE_PREFIXES: [&str; 16] = [
    "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13", "1.14", "1.15",
    "1.99", "1.2.3",
];

/// THE FACES the fixture board renders, asserted live and then recorded as
/// the resolver crate's fixture where `SKEP_RESOLVE_FIXTURE_WRITE` is set —
/// the one command that regenerates `crates/skep-resolve/tests/fixtures/
/// feed.json`. Two bindings are tampered on their way to the mirror by this
/// suite's own transport seam (never by the daemon, which admits no such
/// record): 1.4's `sig` zeroed, 1.14's body spaced.
#[test]
fn the_fixture_board_resolves_live_and_is_recorded_on_demand() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let orgs = fixture_board(port);
    let log = Rc::new(RefCell::new(Vec::new()));
    let tamper = vec![("1.4".to_string(), Tamper::ZeroSig), ("1.14".to_string(), Tamper::Space)];
    let dial = recording_dial(Some(log.clone()), tamper);
    let mdir = tempfile::tempdir().expect("tempdir");
    let hint = hint_for(port);
    let mut mirror = Mirror::open(&hint, mdir.path(), &dial).unwrap_or_else(|e| panic!("the mirror: {e}"));
    assert_eq!(mirror.sync().expect("an empty delta"), 0);
    let suppressed = mirror.index().suppressed().to_vec();
    assert_eq!(suppressed.len(), 2, "{suppressed:?}");
    assert!(suppressed.iter().any(|s| s.link == addr(&orgs["1.4"].binding) && s.cause == Cause::Verdict(Verdict::Unsigned)));
    assert!(suppressed.iter().any(|s| s.link == addr(&orgs["1.14"].binding) && matches!(s.cause, Cause::Malformed(skep_registry::ParseRefusal::NotCanonical))));
    let faces: Vec<(&str, Resolution)> =
        FIXTURE_PREFIXES.iter().map(|p| (*p, resolve_prefix(&mut mirror, p))).collect();
    for (prefix, face) in &faces {
        match (*prefix, face) {
            ("1.2", Resolution::Bound { dial, endpoint, .. }) => {
                assert_eq!(dial.origin.as_str(), "https://acme.example.net");
                assert_eq!(endpoint.record.origins, ["https://acme.example.net"]);
            }
            ("1.3", Resolution::BoundButUnreachable { cause: Unreachable::NoEndpointYet, .. }) => {}
            ("1.4" | "1.14" | "1.99", Resolution::Unregistered { .. }) => {}
            ("1.5", Resolution::RetiredWithHistory { standing, successor: None }) => {
                assert_eq!(standing.history.len(), 2);
                assert_eq!(standing.current.record.account, None);
            }
            ("1.6", Resolution::Bound { standing, .. }) => {
                let honored: Vec<bool> = standing.history.iter().map(|b| b.record.honored).collect();
                assert_eq!(honored, [true, false, false, true]);
                assert_eq!(standing.current.record.account.as_ref().map(ToString::to_string), Some(orgs["1.6"].account.clone()));
            }
            ("1.7", Resolution::Bound { dial, .. }) => assert_eq!(dial.origin.as_str(), "https://seven.example"),
            ("1.8", Resolution::UnreachableByPolicy { term: Term::Scheme, member, .. }) => assert_eq!(member, "http://plain.example"),
            ("1.9", Resolution::UnreachableByPolicy { term: Term::Host { yielded }, .. }) => {
                assert_eq!(yielded, &["127.0.0.1".parse::<IpAddr>().unwrap()]);
            }
            ("1.10", Resolution::DialNotMade { member, .. }) => assert_eq!(member, ONION),
            ("1.11", Resolution::Bound { dial, members, .. }) => {
                assert_eq!(dial.member_index, 1);
                assert!(matches!(members[0], MemberOutcome::NotDialed { .. }));
            }
            ("1.12", Resolution::UnreachableByPolicy { term: Term::Host { yielded }, .. }) => {
                assert_eq!(yielded, &["127.0.0.1".parse::<IpAddr>().unwrap()], "this resolver's own yield at a name");
            }
            ("1.13", Resolution::Bound { dial, .. }) => assert_eq!(dial.origin.as_str(), "https://thirteen.example"),
            ("1.15", Resolution::BoundButUnreachable { cause: Unreachable::DeadOrigin { member }, .. }) => assert_eq!(member, "https://dead.example"),
            ("1.2.3", Resolution::HopNotMade { parent, .. }) => assert!(matches!(**parent, Resolution::Bound { .. })),
            (prefix, face) => panic!("{prefix}: {} unexpected: {face:?}", face.face()),
        }
    }
    // THE SET AS OF THE POSITION: every binding was signed by the device key
    // the registrar has since retired; the claimant's current set holds the
    // anchor and the rotated key alone.
    let device = Fingerprint::of(&public_key_of(&device_key()));
    for (prefix, face) in &faces {
        if let Some(standing) = face.standing() {
            assert_eq!(standing.current.verdict, Verdict::Signed(device), "{prefix}");
        }
    }
    let claimant = mirror.claim().map(|(_, c)| c.clone()).expect("the claim");
    let current: Vec<Fingerprint> = mirror
        .current_keys(&claimant)
        .expect("read")
        .expect("the table at the head")
        .into_iter()
        .map(|e| Fingerprint::of(&e.key))
        .collect();
    assert!(!current.contains(&device), "the device key is retired: {current:?}");
    assert!(current.contains(&Fingerprint::of(&public_key_of(&rotated_registrar_key()))));
    // THE RESUME, so the recording holds the check's reads too (REG-3.18):
    // the copy re-opened against the same source.
    let rows = mirror.stats().rows;
    drop(mirror);
    let resumed = Mirror::open(&hint, mdir.path(), &dial).expect("resumed");
    assert_eq!(*resumed.opened(), Opened::Resumed { checked_rows: rows });
    if std::env::var_os("SKEP_RESOLVE_FIXTURE_WRITE").is_some() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../skep-resolve/tests/fixtures/feed.json");
        let fixture = json!({
            "note": "THE RECORDED FEED the resolver crate's suite replays: every wire exchange a cold mirror made against this daemon suite's fixture board (fourteen orgs under the registrar, one face or one arm of the replay matrix each, then the registrar's key rotation: a third key enrolled and the device key that signed every binding retired), then one empty sync and one resolve per prefix below. Two deliveries are tampered on record by the suite's transport seam, never by the daemon: 1.4's binding carries a zeroed sig (UNSIGNED, suppressed) and 1.14's a spaced body (malformed, suppressed). Regenerate with SKEP_RESOLVE_FIXTURE_WRITE=1 (the resolver crate's README names the command).",
            "hint": hint.to_string(),
            "tampered": { "unsigned": "1.4", "malformed": "1.14" },
            "prefixes": FIXTURE_PREFIXES,
            "exchanges": *log.borrow(),
        });
        fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        fs::write(&path, serde_json::to_string_pretty(&fixture).expect("json")).expect("write the fixture");
    }
    sd.shutdown();
}

// ── the reference cell and the suppress ────────────────────────────────────

/// Every record-deposit link the feed carries, by its kind, read by the
/// suite's own `read_link`: `(kind, link)`.
fn registry_links(port: u16) -> Vec<(BodyKind, String)> {
    let (st, body) = http(port, "GET", "/changes?since=0", None, b"");
    assert_eq!(st, 200);
    let mut out = Vec::new();
    for row in json(&body)["changes"].as_array().expect("changes") {
        if row["op"].as_str() != Some("make_link") || row.get("attest").is_some() {
            continue;
        }
        let Some(address) = row["link"].as_str() else { continue };
        let stored = read_link(port, None, address);
        let ty: Vec<&str> = stored["slots"][2].as_array().map(|s| s.iter().filter_map(|x| x["start"].as_str()).collect()).unwrap_or_default();
        match ty.as_slice() {
            [t] if *t == T_BINDING => out.push((BodyKind::Binding, address.to_string())),
            [t] if *t == T_ENDPOINT => out.push((BodyKind::Endpoint, address.to_string())),
            _ => {}
        }
    }
    out
}

/// THE REFERENCE CELL (rm-2; REG-1.86 (e); the seam investigation's Q7):
/// the resolver's verdict on every row of a generated board equals the
/// daemon's admission — every binding and endpoint link the daemon committed
/// is in the index SIGNED, nothing is suppressed, and a record the daemon
/// REFUSED (a binding signed by a key outside the claimant's set, its atom an
/// orphan no link names) reaches no index: the two refusals never meet a row.
#[test]
fn the_resolvers_verdict_equals_the_daemons_admission_on_every_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let console = console(port);
    let orgs: Vec<Org> =
        (2..5).map(|i| register_org(port, &console, i, &format!("1.{i}"), Some(&["https://org.example"]), 1)).collect();
    // A binding the daemon refuses at its link: signed by a foreign key.
    let foreign = hybrid_signer(&distinct_key(77));
    let body = binding_body("1.9", None);
    let text = signed_registry_text(port, &foreign, CLAIMANT_DOC1, T_BINDING, &[&orgs[0].account], &body).expect("composes");
    let ordinal = next_content_ordinal(port, Some(&console), CLAIMANT_DOC1);
    let v = op(
        port,
        Some(&console),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{T_BINDING}"}}"#,
            json_atom(&text)
        ),
    );
    let orphan = acked_addr(&v);
    let v = op(port, Some(&console), &typed_link_frame(CLAIMANT_DOC1, &[&orphan], &[&orgs[0].account], T_BINDING));
    assert_eq!(v["code"].as_str(), Some("registry_refused"), "{v}");

    let mdir = tempfile::tempdir().expect("tempdir");
    let mirror = cold_mirror(port, mdir.path());
    let index = mirror.index();
    let committed = registry_links(port);
    assert_eq!(committed.len(), 6, "three bindings and three endpoints: {committed:?}");
    for (kind, link) in &committed {
        let link = addr(link);
        let verdict = match kind {
            BodyKind::Binding => index.bindings().find(|b| b.link == link).map(|b| b.verdict.clone()),
            BodyKind::Endpoint => index.all_endpoints().find(|e| e.link == link).map(|e| e.verdict.clone()),
        };
        assert!(matches!(verdict, Some(Verdict::Signed(_))), "{kind:?} {link}: {verdict:?}");
    }
    let counts = index.counts();
    assert_eq!((counts.bindings, counts.endpoints), (3, 3));
    assert!(index.suppressed().is_empty(), "{:?}", index.suppressed());
    assert!(index.bindings().all(|b| b.verdict == Verdict::Signed(Fingerprint::of(&public_key_of(&device_key())))), "every binding the console's key signed");
    for org in &orgs {
        assert!(index.all_endpoints().any(|e| e.home == addr(&org.doc1) && e.verdict == Verdict::Signed(Fingerprint::of(&public_key_of(&org.key)))));
    }
    assert!(!index.bindings().any(|b| b.record.prefix == addr("1.9")), "the refused binding's orphan reaches no index");
    sd.shutdown();
}

/// THE SUPPRESS (rm-2; the investigation §2.5): a body the daemon never
/// admitted cannot reach a committed row on a conforming board, so the one
/// a verifying resolver meets arrives through a SEAM — this suite's own
/// transport, which zeroes one binding's `sig` on its way to the mirror —
/// and is SUPPRESSED from the index, counted UNSIGNED, and the prefix
/// answers UNREGISTERED; the untouched binding beside it resolves.
#[test]
fn a_tampered_body_is_suppressed_by_the_verifying_resolver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let console = console(port);
    let o2 = register_org(port, &console, 2, "1.2", Some(&["https://org.example"]), 0);
    let o3 = register_org(port, &console, 3, "1.3", Some(&["https://org.example"]), 0);
    let dial = recording_dial(None, vec![("1.3".to_string(), Tamper::ZeroSig)]);
    let mdir = tempfile::tempdir().expect("tempdir");
    let mut mirror = Mirror::open(&hint_for(port), mdir.path(), &dial).expect("the mirror");
    assert!(matches!(resolve_prefix(&mut mirror, "1.2"), Resolution::Bound { .. }));
    assert!(matches!(resolve_prefix(&mut mirror, "1.3"), Resolution::Unregistered { .. }));
    assert_eq!(mirror.index().suppressed().len(), 1);
    assert_eq!(mirror.index().suppressed()[0].link, addr(&o3.binding));
    assert_eq!(mirror.index().suppressed()[0].cause, Cause::Verdict(Verdict::Unsigned));
    assert!(mirror.index().bindings().any(|b| b.link == addr(&o2.binding)));
    sd.shutdown();
}

// ── provenance: the courier vector, the root move, no negative cache ───────

/// THE COURIER VECTOR (REG-3.13; R5 (b)): an image of the feed copy with a
/// row omitted, two rows swapped, or a row replayed — every row in it a
/// genuine one — is REFUSED by provenance at the first position that
/// differs from the root's own feed; the untouched copy resumes.
#[test]
fn a_couriers_image_that_omits_reorders_or_replays_rows_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let console = console(port);
    register_org(port, &console, 2, "1.2", Some(&["https://org.example"]), 0);
    register_org(port, &console, 3, "1.3", Some(&["https://org.example"]), 0);
    let own = tempfile::tempdir().expect("tempdir");
    let mirror = cold_mirror(port, own.path());
    let rows = mirror.stats().rows;
    drop(mirror);
    let feed = fs::read_to_string(own.path().join(skep_resolve::FEED_COPY)).expect("the feed copy");
    let lines: Vec<&str> = feed.lines().collect();
    let row_lines: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| l.starts_with("{\"row\":")).map(|(i, _)| i).collect();
    assert_eq!(row_lines.len() as u64, rows);
    let mid = row_lines[row_lines.len() / 2];
    let image = |mutate: &dyn Fn(&mut Vec<String>)| -> PathBuf {
        let courier = tempfile::Builder::new().prefix("courier").tempdir_in(dir.path()).expect("tempdir").keep();
        let mut owned: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        mutate(&mut owned);
        fs::write(courier.join(skep_resolve::FEED_COPY), owned.join("\n") + "\n").expect("write");
        fs::copy(own.path().join(skep_resolve::FETCH_CACHE), courier.join(skep_resolve::FETCH_CACHE)).expect("copy");
        courier
    };
    let at_of = |line: &str| -> u64 { serde_json::from_str::<Value>(line).unwrap()["row"]["at"].as_u64().unwrap() };
    let expected_at = at_of(lines[mid]);
    let omitted = image(&|l| {
        l.remove(mid);
    });
    let swapped = image(&|l| l.swap(mid, mid + 1));
    let replayed = image(&|l| l.insert(mid + 1, l[mid].clone()));
    let next_at = at_of(lines[mid + 1]);
    // The refusal names the HELD row at the first index where the copy and
    // the source part: the row after the omitted one, the later of the two
    // swapped, and the replayed row itself.
    for (what, courier, at) in [("omitted", omitted, next_at), ("swapped", swapped, next_at), ("replayed", replayed, expected_at)] {
        let refused = Mirror::open(&hint_for(port), &courier, &skep_resolve::dial_http).err();
        assert_eq!(refused, Some(MirrorError::Refused(Refusal::Diverged { at })), "{what}");
    }
    let untouched = image(&|_| {});
    let resumed = Mirror::open(&hint_for(port), &untouched, &skep_resolve::dial_http).expect("the untouched copy");
    assert_eq!(*resumed.opened(), Opened::Resumed { checked_rows: rows });
    sd.shutdown();
}

/// THE ROOT MOVE (REG-3.18, REG-3.19; R5 (b)): the same lineage served at a
/// second origin RESUMES by the byte-identical check — every held row and
/// head pair answered the same, the delta synced; a source whose head is
/// BELOW the mirror's position (a root brought up from a backup) is
/// refused as SOURCE BEHIND; a source whose frontier DIVERGES below the
/// mirror's head is refused as DIVERGED; a root of another GENESIS is
/// refused at the base as a REALM MISMATCH (REG-3.42), the hint's genesis
/// fingerprint and the one found both named.
#[test]
fn a_root_move_under_the_same_lineage_resumes_and_its_refusals_are_named() {
    let dir_a = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir_a.path());
    let port = sd.port();
    let console = console(port);
    register_org(port, &console, 2, "1.2", Some(&["https://org.example"]), 0);
    sd.shutdown();
    let early = tempfile::tempdir().expect("tempdir");
    copy_dir(dir_a.path(), early.path());
    // The lineage goes on at A: a second org.
    let sd = spawn(dir_a.path());
    let port = sd.port();
    let console_again = self::console(port);
    register_org(port, &console_again, 3, "1.3", Some(&["https://org.example"]), 0);
    let mdir = tempfile::tempdir().expect("tempdir");
    let mut mirror = cold_mirror(port, mdir.path());
    assert!(matches!(resolve_prefix(&mut mirror, "1.3"), Resolution::Bound { .. }));
    let held = mirror.head();
    let rows = mirror.stats().rows;
    drop(mirror);
    sd.shutdown();

    // THE MOVE: the same journal at a new address.
    let dir_b = tempfile::tempdir().expect("tempdir");
    copy_dir(dir_a.path(), dir_b.path());
    let sd_b = spawn(dir_b.path());
    let mut moved = Mirror::open(&hint_for(sd_b.port()), mdir.path(), &skep_resolve::dial_http).expect("resumed");
    assert_eq!(*moved.opened(), Opened::Resumed { checked_rows: rows });
    assert_eq!(moved.head(), held);
    assert!(matches!(resolve_prefix(&mut moved, "1.3"), Resolution::Bound { .. }));
    // The delta after the move is synced.
    let console_b = self::console(sd_b.port());
    register_org(sd_b.port(), &console_b, 4, "1.4", Some(&["https://org.example"]), 0);
    assert!(moved.sync().expect("sync") > 0);
    assert!(matches!(resolve_prefix(&mut moved, "1.4"), Resolution::Bound { .. }));
    drop(moved);
    sd_b.shutdown();

    // SOURCE BEHIND: a root brought up from the early backup.
    let behind_dir = tempfile::tempdir().expect("tempdir");
    copy_dir(early.path(), behind_dir.path());
    let sd_behind = spawn(behind_dir.path());
    let refused = Mirror::open(&hint_for(sd_behind.port()), mdir.path(), &skep_resolve::dial_http).err();
    assert!(matches!(refused, Some(MirrorError::Refused(Refusal::SourceBehind { .. }))), "{refused:?}");
    sd_behind.shutdown();

    // DIVERGED: the early backup, written past the fork with another act.
    let diverged_dir = tempfile::tempdir().expect("tempdir");
    copy_dir(early.path(), diverged_dir.path());
    let sd_div = spawn(diverged_dir.path());
    let console_d = self::console(sd_div.port());
    register_org(sd_div.port(), &console_d, 93, "1.3", Some(&["https://other.example"]), 0);
    let refused = Mirror::open(&hint_for(sd_div.port()), mdir.path(), &skep_resolve::dial_http).err();
    assert!(matches!(refused, Some(MirrorError::Refused(Refusal::Diverged { .. }))), "{refused:?}");
    sd_div.shutdown();

    // A DIFFERENT GENESIS: a board claimed under other keys, read cold under
    // this suite's realm.
    let other_dir = tempfile::tempdir().expect("tempdir");
    let sd_c = spawn_unclaimed(other_dir.path());
    let (other_anchor, other_device) = (distinct_key(60), distinct_key(61));
    let seat = seed_partial(sd_c.port(), CLAIMANT_PRINCIPAL, &[(&other_anchor, true), (&other_device, false)]);
    let signed = open_signed_session(sd_c.port(), CLAIMANT_PRINCIPAL, &other_device);
    expect_resp(&op(sd_c.port(), Some(&signed), &claim_frame(&seat.doc1, &seat.account)), "ack_addr");
    assert!(claimed(sd_c.port()));
    let fresh = tempfile::tempdir().expect("tempdir");
    let refused = Mirror::open(&hint_for(sd_c.port()), fresh.path(), &skep_resolve::dial_http).err();
    let found = RealmId::genesis_fingerprint(&[Fingerprint::of(&public_key_of(&other_anchor)), Fingerprint::of(&public_key_of(&other_device))]);
    assert_eq!(refused, Some(MirrorError::Refused(Refusal::RealmMismatch { expected: suite_realm(), found })));
    assert!(!fresh.path().join(skep_resolve::FEED_COPY).exists(), "a refused base writes no copy");
    sd_c.shutdown();
}

/// NO NEGATIVE CACHE (REG-3.10): a prefix no binding names is UNREGISTERED
/// now and asked again at the next delta — bound meanwhile, it resolves
/// after one sync, never remembered as absent.
#[test]
fn a_missing_binding_is_re_asked_at_the_next_delta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let console = console(port);
    register_org(port, &console, 2, "1.2", Some(&["https://org.example"]), 0);
    let mdir = tempfile::tempdir().expect("tempdir");
    let mut mirror = cold_mirror(port, mdir.path());
    assert!(matches!(resolve_prefix(&mut mirror, "1.3"), Resolution::Unregistered { .. }));
    assert!(matches!(resolve_prefix(&mut mirror, "1.3"), Resolution::Unregistered { .. }));
    register_org(port, &console, 3, "1.3", Some(&["https://org.example"]), 0);
    assert!(matches!(resolve_prefix(&mut mirror, "1.3"), Resolution::Unregistered { .. }), "not yet synced");
    assert!(mirror.sync().expect("sync") > 0);
    assert!(matches!(resolve_prefix(&mut mirror, "1.3"), Resolution::Bound { .. }));
    sd.shutdown();
}

// ── the chain walk and the end-to-end ──────────────────────────────────────

/// REARRANGE the registrar's doc 1 so every binding atom is un-arranged at
/// the head (REG-3.25's case): a first shot carrying the ceremony atom and
/// the binding atoms mints `D.1`, the version that arranged them; a second
/// carrying the ceremony atom alone mints `D.2`, the head, where no binding
/// atom stands.
/// The hires' enroll atoms are arranged in neither member: the daemon's fold
/// reads a credential record by its link's address and never by its
/// arrangement, and the walk's subjects here are the bindings. The shots
/// carry their copied atoms by value in the signed body, so each is kept
/// under the daemon's entry-body budget by taking one class of atom at a
/// time. Answers the two members.
fn un_arrange_bindings(port: u16, console: &str, bindings: &[&str]) -> (String, String) {
    let extent = content_extent(port, None, CLAIMANT_DOC1);
    let binding_ordinals: Vec<u64> = bindings
        .iter()
        .map(|link| {
            let stored = read_link(port, None, link);
            let from = stored["slots"][0][0]["start"].as_str().expect("from");
            from.rsplit('.').next().expect("ordinal").parse().expect("a count")
        })
        .collect();
    // The ceremony atom rides both shots: the second shot's signer reads
    // the values it places off the head the first shot leaves.
    let ceremony = [run(CLAIMANT_DOC1, &format!("{CLAIMANT_DOC1}.0.1.1"), 1)];
    let first: Vec<String> = ceremony
        .iter()
        .cloned()
        .chain(binding_ordinals.iter().map(|n| run(CLAIMANT_DOC1, &format!("{CLAIMANT_DOC1}.0.1.{n}"), 1)))
        .collect();
    let v = op(port, Some(console), &publish_frame(CLAIMANT_DOC1, None, None, &first));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the first shot, {} runs: {v}", first.len());
    let d1 = acked_addr(&v);
    assert_eq!(content_extent(port, None, &d1), first.len() as u64);
    let v = op(port, Some(console), &publish_frame(CLAIMANT_DOC1, Some((&d1, first.len() as u64)), None, &ceremony));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the second shot: {v}");
    let d2 = acked_addr(&v);
    assert!(extent > bindings.len() as u64);
    (d1, d2)
}

/// THE CHAIN WALK (REG-3.25; REG-3.26; rs-Q11): every binding atom
/// un-arranged at the registrar's doc 1's head is recovered by the walk
/// down the home's chain — the head missed, `D.2` missed, `D.1` held it —
/// never off the arranged head and never by the position read; every
/// binding resolves as before.
#[test]
fn an_un_arranged_atom_is_recovered_by_the_homes_chain_walk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let console = console(port);
    let orgs: Vec<Org> =
        (2..4).map(|i| register_org(port, &console, i, &format!("1.{i}"), Some(&["https://org.example"]), 0)).collect();
    let bindings: Vec<&str> = orgs.iter().map(|o| o.binding.as_str()).collect();
    let (d1, d2) = un_arrange_bindings(port, &console, &bindings);
    assert_eq!(content_extent(port, None, CLAIMANT_DOC1), content_extent(port, None, &d2), "the bare address floats to the head");
    assert_eq!((content_extent(port, None, &d1), content_extent(port, None, &d2)), (3, 1), "the bindings in D.1 beside the ceremony atom, the ceremony atom alone at the head");
    let mdir = tempfile::tempdir().expect("tempdir");
    let mut mirror = cold_mirror(port, mdir.path());
    let walk = mirror.stats().chain_walk;
    assert_eq!(walk.atoms, 2, "{walk:?}");
    assert_eq!(walk.versions_visited, 4, "D.2 missed and D.1 held it, twice: {walk:?}");
    assert_eq!(walk.position_reads, 0, "never the position read where a version holds it");
    assert!(walk.reads >= 4, "{walk:?}");
    assert_eq!(mirror.chain_members_of(&addr(CLAIMANT_DOC1)), [addr(&d1), addr(&d2)]);
    for org in &orgs {
        assert!(matches!(resolve_prefix(&mut mirror, &org.prefix), Resolution::Bound { .. }), "{}", org.prefix);
    }
    assert!(mirror.index().suppressed().is_empty());
    sd.shutdown();
}

/// THE END-TO-END (REG-3.7, REG-3.9; the seam investigation's §0 walk): one
/// org registered by the registrar's console — its account hired, its prefix
/// bound, its doc 1 minted, its endpoint deposited — resolved from the ROOT
/// HINT alone by a cold resolver in a fresh directory: BOUND, with the
/// account's key set as the board folds it, the endpoint current, the member
/// it would dial and the verdicts beside every record.
#[test]
fn one_org_registered_by_the_console_resolves_from_the_hint_by_a_cold_resolver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let console = console(port);
    let org = register_org(port, &console, 5, "1.5", Some(&["https://acme.example", "https://acme.example.net"]), 0);
    let mdir = tempfile::tempdir().expect("tempdir");
    let hint = RootHint::parse(&hint_for(port).to_string()).expect("the one line parses back");
    let mut mirror = Mirror::open(&hint, mdir.path(), &skep_resolve::dial_http).expect("a cold resolver");
    assert_eq!(*mirror.opened(), Opened::Bootstrapped);
    assert_eq!(mirror.claim().map(|(_, c)| c.to_string()).as_deref(), Some(CLAIMANT_ACCOUNT));
    match resolve_prefix(&mut mirror, "1.5") {
        Resolution::Bound { standing, keys, endpoint, dial, members } => {
            assert_eq!(standing.current.link, addr(&org.binding));
            assert_eq!(standing.current.record.account, Some(addr(&org.account)));
            assert_eq!(standing.current.verdict, Verdict::Signed(Fingerprint::of(&public_key_of(&device_key()))));
            assert_eq!(standing.history.len(), 1);
            let live = op(port, None, &format!(r#"{{"op":"key_set","account":"{}"}}"#, org.account));
            let live: Vec<String> = live["enrolled"].as_array().unwrap().iter().map(|e| e["fingerprint"].as_str().unwrap().to_string()).collect();
            let keys = keys.as_ref().expect("the table at the head");
            assert_eq!(keys.iter().map(|e| Fingerprint::of(&e.key).to_hex()).collect::<Vec<_>>(), live, "the key set as the board folds it");
            assert_eq!(endpoint.link, addr(org.endpoint.as_ref().unwrap()));
            assert_eq!(endpoint.verdict, Verdict::Signed(Fingerprint::of(&public_key_of(&org.key))));
            assert_eq!(endpoint.record.origins, ["https://acme.example", "https://acme.example.net"]);
            assert_eq!((dial.member_index, dial.origin.as_str()), (0, "https://acme.example"));
            assert_eq!(dial.addresses, ["93.184.216.34".parse::<IpAddr>().unwrap()]);
            assert_eq!(members.len(), 2);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(resolve_prefix(&mut mirror, "1.6"), Resolution::Unregistered { .. }));
    sd.shutdown();
}

// ── the measurements (reported, never asserted) ────────────────────────────

/// Where a measurement cell appends its line beside printing it.
fn report(line: &str) {
    println!("{line}");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/resolve-measurements.txt");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = writeln!(f, "{line}");
    }
}

fn ms(d: Duration) -> String {
    format!("{:.1}ms", d.as_secs_f64() * 1000.0)
}

fn secs(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

/// THE BOARD GENERATOR's record signer: a registry or credential record's
/// text SIGNED at the record grade over the frame the daemon composes —
/// `H.1`'s pair, the home's account by address arithmetic, the home, the
/// type, the target, the sig-less canonical body — with no read of the
/// board: the harness holds every member already. Sent WITHOUT an entry
/// `attest`, as a conforming client sends a record deposit (the atom's
/// insert is exempt where it parses as a record carrying its `sig`, and the
/// link takes the record's own sequence), so each record costs one hybrid
/// signature instead of the suite helpers' three.
struct RecordSigner {
    board: skep_identity::BoardTerm,
    alg: &'static str,
}

impl RecordSigner {
    fn at(port: u16) -> RecordSigner {
        RecordSigner {
            board: board_term(port).expect("a claimed board has its H.1"),
            alg: skep_identity::SigAlgRow::of_tag(FIXTURE_TAG).expect("tag 1").token,
        }
    }

    fn sign(&self, signer: &skep_signature::HybridSigner, home: &str, ty: &str, to: &[&str], sigless: &str) -> String {
        let home = addr(home);
        let account = skep_resolve::account_of_document(&home).expect("a doc 1's account");
        let ty = addr(ty);
        let to: Vec<Address> = to.iter().map(|a| addr(a)).collect();
        let body = skep_identity::entry_body_record(skep_identity::RecordRows {
            ty: &ty,
            to: &to,
            replaces: None,
            lineage_fork_point: None,
            sigless_canonical_record: sigless.as_bytes(),
        });
        let frame = skep_identity::entry_frame(self.alg, self.board, &account, skep_identity::DocTerm::One(&home), &body);
        hex(&signer.sign(&frame))
    }

    /// A registry body signed for a deposit in `home` typed `ty` naming `to`.
    fn registry(&self, signer: &skep_signature::HybridSigner, home: &str, ty: &str, to: &[&str], body: &str) -> String {
        let kind = if ty == T_BINDING { BodyKind::Binding } else { BodyKind::Endpoint };
        let record = skep_registry::parse(kind, body.as_bytes()).expect("canonical");
        let sig = self.sign(signer, home, ty, to, &record.canonical_sigless());
        encode(&record.body, Some(&sig))
    }

    /// An enroll record of one device-flagged key, signed for a deposit in
    /// `home` naming `to`.
    fn enroll(&self, signer: &skep_signature::HybridSigner, home: &str, to: &str, key: &SigningKey) -> String {
        let entries = [skep_identity::Enrollment::new(public_key_of(key), false, None).expect("no label")];
        let sigless = canonical_record(&entries, None);
        let sig = self.sign(signer, home, T_ENROLL, &[to], &sigless);
        canonical_record(&entries, Some(&sig))
    }
}

/// A record deposit as the generator makes it: the atom inserted DECLARED
/// under `ty` at `ordinal` of `home`, then its link to `to` — both frames
/// sent as written, no entry `attest`.
fn deposit_as_written(port: u16, token: &str, home: &str, ordinal: u64, ty: &str, to: &[&str], text: &str) -> String {
    let v = op_as_written(
        port,
        Some(token),
        &format!(
            r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{ty}"}}"#,
            json_atom(text)
        ),
    );
    let atom = acked_addr(&v);
    let v = op_as_written(port, Some(token), &typed_link_frame(home, &[atom.as_str()], to, ty));
    acked_addr(&v)
}

/// How many orgs' own doc-1 writes run at once in the generator's second
/// phase: every org's home is its own, so the writes never meet, and the
/// client-side signing — the harness's dominant cost in a debug build — runs
/// on every core.
const GENERATOR_THREADS: usize = 8;

/// A generated registry board of `n` orgs with `k` key acts each (the
/// investigation §3.1's harness): each org a `delegate`, a genesis enroll, a
/// binding atom + link, a doc-1 mint, an endpoint atom + link and `k` key
/// acts — the same rows `register_org` writes, by a faster hand: the
/// registrar's doc-1 writes serial in one phase, each org's own doc-1 writes
/// in parallel in a second. Progress is printed per thousand so a run cut at
/// a cap still reports how far it reached.
fn generate_board(port: u16, console: &str, n: u64, k: usize) -> Vec<Org> {
    let t = Instant::now();
    let signer = RecordSigner::at(port);
    let console_key = hybrid_signer(&device_key());
    let boot = open_session(port, 0);
    // PHASE ONE, serial: the account, its hire and its binding, every one a
    // write into the registrar's doc 1.
    let mut ordinal = content_extent(port, None, CLAIMANT_DOC1) + 1;
    let mut next_account = next_prefix_under(port, Some(&boot), "1");
    let mut seeds: Vec<(u64, String, String, String)> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let principal = ORG_PRINCIPAL_BASE + i + 2;
        let prefix = format!("1.{}", i + 2);
        let account = next_account.clone();
        expect_resp(
            &op(port, Some(&boot), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{principal}}}"#)),
            "ack_addr",
        );
        next_account = next_prefix_under(port, Some(&boot), "1");
        let key = org_key(principal);
        let enroll = signer.enroll(&console_key, CLAIMANT_DOC1, &account, &key);
        deposit_as_written(port, console, CLAIMANT_DOC1, ordinal, T_ENROLL, &[&account], &enroll);
        ordinal += 1;
        let body = binding_body(&prefix, None);
        let text = signer.registry(&console_key, CLAIMANT_DOC1, T_BINDING, &[&account], &body);
        let binding = deposit_as_written(port, console, CLAIMANT_DOC1, ordinal, T_BINDING, &[&account], &text);
        ordinal += 1;
        seeds.push((principal, prefix, account, binding));
        if n >= 1_000 && (i + 1) % 1_000 == 0 {
            report(&format!("  … N={n} k={k}: {} orgs hired and bound in {}", i + 1, secs(t.elapsed())));
        }
    }
    // PHASE TWO, parallel: each org's own session, doc 1, endpoint and key
    // acts.
    let chunk = (seeds.len() / GENERATOR_THREADS).max(1);
    let signer = &signer;
    let orgs: Vec<Org> = std::thread::scope(|scope| {
        let handles: Vec<_> = seeds
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    let mut out = Vec::with_capacity(part.len());
                    for (principal, prefix, account, binding) in part {
                        let key = org_key(*principal);
                        let node_signed = open_signed_session(port, *principal, &key);
                        let doc1 = mint_doc_one(port, &node_signed, account);
                        let own = hybrid_signer(&key);
                        // The key acts first, the endpoint signed by the latest
                        // key: so the endpoint's epoch reaches the head, and a
                        // board that reclaims its early journal still answers
                        // the table as of the deposit (the mirror's floor
                        // clause).
                        let mut extra_keys = Vec::with_capacity(k);
                        for j in 0..k {
                            let extra = org_key(principal * 100 + j as u64 + 1);
                            let enroll = signer.enroll(&own, &doc1, account, &extra);
                            deposit_as_written(port, &node_signed, &doc1, 1 + j as u64, T_ENROLL, &[account], &enroll);
                            extra_keys.push(extra);
                        }
                        let (latest, latest_session) = match extra_keys.last() {
                            Some(latest) => (hybrid_signer(latest), open_signed_session(port, *principal, latest)),
                            None => (hybrid_signer(&key), node_signed.clone()),
                        };
                        let body = endpoint_body(&["https://org.example"], None);
                        let text = signer.registry(&latest, &doc1, T_ENDPOINT, &[], &body);
                        let endpoint = deposit_as_written(port, &latest_session, &doc1, 1 + k as u64, T_ENDPOINT, &[], &text);
                        out.push(Org {
                            principal: *principal,
                            prefix: prefix.clone(),
                            account: account.clone(),
                            doc1,
                            key,
                            node_signed,
                            binding: binding.clone(),
                            endpoint: Some(endpoint),
                            extra_keys,
                        });
                    }
                    out
                })
            })
            .collect();
        let mut orgs = Vec::with_capacity(seeds.len());
        for h in handles {
            orgs.extend(h.join().expect("a generator thread"));
        }
        orgs
    });
    let mut orgs = orgs;
    orgs.sort_by_key(|o| o.principal);
    if n >= 1_000 {
        report(&format!("  … N={n} k={k}: every org's doc 1, endpoint and key acts written in {}", secs(t.elapsed())));
    }
    orgs
}

/// ONE MEASUREMENT CELL (the investigation §3.1, §3.3, §3.4), debug build:
/// the board generated; a cold mirror from the hint alone — the feed's rows,
/// bytes and pages, every fetch by kind, the verify time per record, the
/// fold, the wall time to the first resolve; the warm `since=N` delta for
/// one endpoint change; the guest-reading resolve of one prefix with no
/// mirror (REG-3.24); and, where `chain_walk` is asked, the registrar's doc
/// 1 rearranged so every binding atom is un-arranged at the head and the
/// walk's reads and time per atom against a direct value read (§3.3). The
/// per-row verify is the native hybrid verify alone: no WASM build exists in
/// this workspace, so §3.4's ratio is not measured.
fn measure(n: u64, k: usize, chain_walk: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let console = console(port);
    let t = Instant::now();
    let orgs = generate_board(port, &console, n, k);
    let generated = t.elapsed();
    let feed_rows = head_position(port);

    // THE COLD BOOTSTRAP from the hint alone.
    let mdir = tempfile::tempdir().expect("tempdir");
    let t = Instant::now();
    let mut mirror = cold_mirror(port, mdir.path());
    let cold = t.elapsed();
    let s = mirror.stats();
    let t = Instant::now();
    let first = resolve_prefix(&mut mirror, &orgs[0].prefix);
    let first_resolve = t.elapsed();
    assert!(matches!(first, Resolution::Bound { .. }), "{}", first.face());
    let per_record = if s.records > 0 { s.verify_time / s.records as u32 } else { Duration::ZERO };
    report(&format!(
        "N={n} k={k} | generated in {} ({feed_rows} positions) | COLD: rows={} pages={} bytes={} fetches={} (read_link={} retrieve={} image={} span_set={} key_set={} find_links={} op_at={} chain={} health={}) records={} verify={} total ({} per record) fold={} bootstrap={} first_resolve={} copy_bytes={} suppressed={}",
        secs(generated),
        s.rows,
        s.pages,
        s.feed_bytes,
        s.reads.total(),
        s.reads.read_link,
        s.reads.retrieve,
        s.reads.image,
        s.reads.span_set,
        s.reads.key_set,
        s.reads.find_links,
        s.reads.op_at,
        s.reads.chain,
        s.reads.health,
        s.records,
        ms(s.verify_time),
        ms(per_record),
        ms(s.fold_time),
        secs(cold),
        ms(first_resolve),
        s.copy_bytes,
        mirror.index().suppressed().len(),
    ));

    // THE WARM DELTA: one endpoint change, signed by the org's latest key.
    let signer = match orgs[0].extra_keys.last() {
        Some(latest) => open_signed_session(port, orgs[0].principal, latest),
        None => orgs[0].node_signed.clone(),
    };
    let moved = deposit_endpoint(port, &signer, &orgs[0].doc1, &["https://moved.example"], orgs[0].endpoint.as_deref());
    let before = mirror.stats();
    let t = Instant::now();
    let rows = mirror.sync().expect("the delta");
    let warm = t.elapsed();
    let after = mirror.stats();
    let r = resolve_prefix(&mut mirror, &orgs[0].prefix);
    match &r {
        Resolution::Bound { endpoint, .. } => assert_eq!(endpoint.link, addr(&moved)),
        other => panic!("{other:?}"),
    }
    report(&format!(
        "N={n} k={k} | WARM since={}: rows={rows} fetches={} bytes={} time={}",
        before.rows,
        after.reads.total() - before.reads.total(),
        after.feed_bytes - before.feed_bytes,
        ms(warm),
    ));

    // THE GUEST-READING RESOLVE with no mirror.
    let board = Board::new(skep_resolve::dial_http(&hint_for(port).origins()[0]).expect("http"));
    let target = &orgs[orgs.len() / 2];
    let (guest, cost) = guest_resolve(&board, &addr(&target.prefix), &names(), &Transports::default()).expect("the guest resolve");
    assert_eq!(dial_of(&guest), dial_of(&resolve_prefix(&mut mirror, &target.prefix)), "the guest and the mirror agree on the dial");
    report(&format!(
        "N={n} k={k} | GUEST (no mirror, REG-3.24): candidate_bindings_scanned={} atoms_read={} reads={} time={}",
        cost.candidate_bindings_scanned, cost.atoms_read, cost.reads, ms(cost.time),
    ));

    // THE CHAIN WALK (§3.3) against a direct value read.
    if chain_walk {
        let t = Instant::now();
        let direct_reads = 20u32;
        for pos in 2..2 + direct_reads as u64 {
            let v = board.op(&json!({ "op": "retrieve_v", "specs": [{ "doc": CLAIMANT_DOC1, "span": { "start": format!("1.{pos}"), "width": "0.1" } }] })).expect("a read");
            assert_eq!(v["resp"].as_str(), Some("delivery"));
        }
        let direct = t.elapsed() / direct_reads;
        let bindings: Vec<&str> = orgs.iter().map(|o| o.binding.as_str()).collect();
        let t = Instant::now();
        let (_, _) = un_arrange_bindings(port, &console, &bindings);
        let rearranged = t.elapsed();
        let wdir = tempfile::tempdir().expect("tempdir");
        let t = Instant::now();
        let walked = cold_mirror(port, wdir.path());
        let cold2 = t.elapsed();
        let w = walked.stats().chain_walk;
        let per_atom = if w.atoms > 0 { w.time / w.atoms as u32 } else { Duration::ZERO };
        report(&format!(
            "N={n} k={k} | CHAIN WALK (REG-3.25): rearranged in {} | atoms={} versions_visited={} reads={} ({:.2} per atom) time/atom={} position_reads={} | direct value read={} | bootstrap over the rearranged board={}",
            secs(rearranged),
            w.atoms,
            w.versions_visited,
            w.reads,
            if w.atoms > 0 { w.reads as f64 / w.atoms as f64 } else { 0.0 },
            ms(per_atom),
            w.position_reads,
            ms(direct),
            secs(cold2),
        ));
    }
    sd.shutdown();
}

#[test]
fn measure_n10_k0() {
    measure(10, 0, true);
}

#[test]
fn measure_n10_k2() {
    measure(10, 2, false);
}

#[test]
fn measure_n10_k8() {
    measure(10, 8, false);
}

#[test]
fn measure_n1000_k0() {
    measure(1_000, 0, true);
}

#[test]
fn measure_n1000_k2() {
    measure(1_000, 2, false);
}

/// The two cells too heavy for the gate, run ALONE by their own command:
/// `SKEP_RESOLVE_MEASURE_ALONE=1 cargo nextest run -p skepd --profile full
/// -E 'test(/^resolve::measure_alone_/)'`. Without the variable each passes
/// at once, saying so. An `#[ignore]` would not keep them out: the gate of
/// record runs with `--run-ignored all`, and the `full` profile caps a test
/// at 600 s — N = 1,000 at eight key acts is daemon-bound at eight minutes
/// alone on this Mac, and N = 100,000's generation is hours.
fn alone() -> bool {
    if std::env::var_os("SKEP_RESOLVE_MEASURE_ALONE").is_some() {
        return true;
    }
    report("  (a measurement cell run alone by its own command: set SKEP_RESOLVE_MEASURE_ALONE=1)");
    false
}

#[test]
fn measure_alone_n1000_k8() {
    if alone() {
        measure(1_000, 8, false);
    }
}

/// The N = 100,000 cell: the board's generation alone is a hundred thousand
/// orgs of signed writes, so under the `full` profile's cap the progress
/// lines are what a run reports.
#[test]
fn measure_alone_n100000_k2() {
    if alone() {
        measure(100_000, 2, false);
    }
}



