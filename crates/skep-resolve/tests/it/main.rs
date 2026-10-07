//! The crate's one integration-test target: every suite below is a module of
//! this binary, over THE RECORDED FEED — `tests/fixtures/feed.json`, the
//! wire exchanges a cold mirror made against the daemon suite's fixture board
//! (that suite's `resolve.rs` records it; the README names the one command).
//! A board is never spawned here: the transport REPLAYS the recording, and
//! an exchange the recording lacks is a panic naming it.

mod index;
mod mirror;
mod origin;
mod walk;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::rc::Rc;

use serde_json::Value;
use skep_address::Address;
use skep_resolve::{
    Method, Mirror, NameResolver, Origin, Resolution, RootHint, Transport, TransportError, Transports,
};

/// The recording, parsed: the hint it was made under, the two tampered
/// prefixes, and every exchange keyed by its request.
pub struct Fixture {
    pub hint: RootHint,
    pub tampered_unsigned: String,
    pub tampered_malformed: String,
    pub prefixes: Vec<String>,
    exchanges: HashMap<(String, String, String), (u16, String)>,
}

pub fn fixture() -> Rc<Fixture> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/feed.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e} — {REGENERATE}", path.display()));
    let v: Value = serde_json::from_str(&text).expect("the fixture is JSON");
    let hint = RootHint::parse(v["hint"].as_str().expect("a hint line")).expect("the hint parses");
    let mut exchanges = HashMap::new();
    for e in v["exchanges"].as_array().expect("exchanges") {
        let key = (
            e["method"].as_str().expect("method").to_string(),
            e["path"].as_str().expect("path").to_string(),
            e["request"].as_str().expect("request").to_string(),
        );
        exchanges.insert(key, (e["status"].as_u64().expect("status") as u16, e["response"].as_str().expect("response").to_string()));
    }
    Rc::new(Fixture {
        hint,
        tampered_unsigned: v["tampered"]["unsigned"].as_str().expect("the unsigned prefix").to_string(),
        tampered_malformed: v["tampered"]["malformed"].as_str().expect("the malformed prefix").to_string(),
        prefixes: v["prefixes"].as_array().expect("prefixes").iter().map(|p| p.as_str().unwrap().to_string()).collect(),
        exchanges,
    })
}

const REGENERATE: &str = "regenerate the fixture: SKEP_RESOLVE_FIXTURE_WRITE=1 cargo nextest run -p skepd -E 'test(=resolve::the_fixture_board_resolves_live_and_is_recorded_on_demand)'";

/// The transport that answers from the recording and dials nothing.
pub struct Replay(pub Rc<Fixture>);

impl Transport for Replay {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let key = (method.to_string(), path.to_string(), String::from_utf8_lossy(body).into_owned());
        match self.0.exchanges.get(&key) {
            Some((status, response)) => Ok((*status, response.clone().into_bytes())),
            None => panic!("an exchange the fixture did not record: {method} {path} {}\n{REGENERATE}", key.2),
        }
    }
}

/// A dial that replays the fixture whatever origin is named.
pub fn replay_dial(fixture: Rc<Fixture>) -> impl Fn(&Origin) -> Result<Box<dyn Transport>, TransportError> {
    move |_: &Origin| -> Result<Box<dyn Transport>, TransportError> { Ok(Box::new(Replay(fixture.clone()))) }
}

/// A mirror bootstrapped from the fixture under `dir`.
pub fn open_fixture_mirror(dir: &Path) -> (Rc<Fixture>, Mirror) {
    let fixture = fixture();
    let dial = replay_dial(fixture.clone());
    let mirror = Mirror::open(&fixture.hint, dir, &dial).unwrap_or_else(|e| panic!("the fixture mirror: {e}"));
    (fixture, mirror)
}

/// THIS RESOLVER's own resolution of a name, fixed (REG-3.35): the daemon
/// suite's table, so a face reads the same here as it did at the recording.
pub struct Names(HashMap<&'static str, Vec<IpAddr>>);

impl NameResolver for Names {
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        Ok(self.0.get(host).cloned().unwrap_or_default())
    }
}

pub fn public_ip() -> IpAddr {
    "93.184.216.34".parse().unwrap()
}

pub fn loopback() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

pub fn names() -> Names {
    let mut t = HashMap::new();
    for host in [
        "acme.example", "acme.example.net", "stale.example", "four.example", "five.example", "six.example",
        "seven.example", "eleven.example", "thirteen.example", "fourteen.example",
    ] {
        t.insert(host, vec![public_ip()]);
    }
    t.insert("loop.example", vec![loopback()]);
    t.insert("dead.example", Vec::new());
    Names(t)
}

pub fn addr(s: &str) -> Address {
    skep_resolve::parse_address(s).unwrap_or_else(|| panic!("{s} is an address"))
}

pub fn resolve_prefix(mirror: &mut Mirror, prefix: &str) -> Resolution {
    skep_resolve::resolve(mirror, &addr(prefix), &names(), &Transports::default())
        .unwrap_or_else(|e| panic!("resolve {prefix}: {e}"))
}
