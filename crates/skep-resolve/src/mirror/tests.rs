use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::rc::Rc;

use serde_json::json;
use skep_registry::{t_binding, t_endpoint};
use skep_signature::HybridSigner;

use super::*;
use crate::board::unit_span_json;
use crate::http::{Method, Transport, TransportError};
use crate::mirror::testing::{
    answer, binding_text, endpoint_text, enroll_text, hint, hint_of, over, over_hint, realm_of, retire_text, signer, span,
    KeySetArm, Script, TERM,
};
use crate::origin::{NameResolver, Transports};
use crate::walk::resolve;

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

/// The registrar's account and doc 1, and an org's.
const CLAIMANT: &str = "1.0.1";
const REGISTRY: &str = "1.0.1.0.1";
const ORG: &str = "1.0.2";
const ORG_DOC1: &str = "1.0.2.0.1";

fn fp(signer: &HybridSigner) -> Fingerprint {
    Fingerprint::of(signer.public_key())
}

/// A copy held under `dir` for an OFFLINE rebuild: the feed's rows and the
/// fetch cache's lines a mirror wrote — every stored link and every atom,
/// the credential records the table is folded from among them — built by
/// the same deposits a [`Script`] takes.
struct Copy {
    kept: Fetched,
    lines: Vec<Value>,
    rows: Vec<Value>,
    ordinals: BTreeMap<String, u64>,
    link_ordinals: BTreeMap<String, u64>,
    position: u64,
}

impl Copy {
    fn new() -> Copy {
        let mut kept = Fetched::default();
        let lines = vec![kept.keep_board(TERM, &"07".repeat(32)).expect("the term's line")];
        Copy { kept, lines, rows: Vec::new(), ordinals: BTreeMap::new(), link_ordinals: BTreeMap::new(), position: 0 }
    }

    fn bump(of: &mut BTreeMap<String, u64>, home: &Address) -> u64 {
        let n = of.entry(home.to_string()).or_insert(0);
        *n += 1;
        *n
    }

    /// `text` deposited as the next atom of `home` and linked, typed `ty`,
    /// to `to` at the next position, its lines kept; the link's address.
    fn deposit(&mut self, home: &Address, ty: &Address, to: &[Address], text: &str) -> Address {
        let ordinal = Copy::bump(&mut self.ordinals, home);
        let atom = a(&format!("{home}.0.1.{ordinal}"));
        self.lines.extend(self.kept.keep_atom(atom.clone(), text.to_string()));
        self.link(home, ty, vec![atom], to.to_vec())
    }

    /// A claim link in the claimant's own doc 1, no atom.
    fn claim(&mut self, claimant: &Address) -> Address {
        let home = a(&format!("{claimant}.0.1"));
        self.link(&home, &commons_type(&[3]), vec![claimant.clone()], Vec::new())
    }

    fn link(&mut self, home: &Address, ty: &Address, from: Vec<Address>, to: Vec<Address>) -> Address {
        let k = Copy::bump(&mut self.link_ordinals, home);
        let address = a(&format!("{home}.0.2.{k}"));
        self.position += 1;
        let stored = StoredLink { at: self.position, address: address.clone(), home: home.clone(), ty: Some(ty.clone()), from, to };
        self.lines.extend(self.kept.keep_link(stored));
        self.rows.push(json!({ "at": self.position, "op": "make_link", "link": address.to_string(), "docs": [home.to_string()] }));
        address
    }

    /// A row at the next position whose link the cache holds at ANOTHER
    /// position and home — the courier's line — the row's home `home`.
    fn row_for(&mut self, link: &Address, home: &Address) {
        self.position += 1;
        self.rows.push(json!({ "at": self.position, "op": "make_link", "link": link.to_string(), "docs": [home.to_string()] }));
    }

    /// The copy written under `dir` and rebuilt offline.
    fn rebuilt(&self, dir: &Path) -> Mirror {
        let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
        let rows = self.rows.iter().map(|row| json!({ "row": row }));
        let feed: String = std::iter::once(&header).cloned().chain(rows).map(|line| format!("{line}\n")).collect();
        fs::write(dir.join(FEED_COPY), feed).expect("the feed copy");
        fs::write(dir.join(FETCH_CACHE), self.lines.iter().map(|line| format!("{line}\n")).collect::<String>()).expect("the cache");
        Mirror::rebuild_offline(&hint(), dir).expect("rebuilt")
    }
}

/// A copy whose registrar `1.0.1` holds `registrar`'s key from its genesis
/// at 1 and claimed at 2.
fn claimed_copy(registrar: &HybridSigner) -> Copy {
    let (registry, claimant) = (a(REGISTRY), a(CLAIMANT));
    let mut copy = Copy::new();
    copy.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(None, &registry, &claimant, &[(registrar.public_key(), true)]));
    copy.claim(&claimant);
    copy
}

/// THE BINDING-WRITING ACCOUNT (R5 (g); REG-2.8, REG-2.6): a binding-typed
/// record an org deposits in its own doc 1 — signed by the org's own key, so
/// the board's home check and the verify would both pass it — binds nothing:
/// it is counted apart, never judged, and its prefix has no standing; the
/// registrar's own binding, deposited the same way in the claimant's doc 1,
/// is SIGNED and stands. The copy is rebuilt offline, every fetch served
/// from a cache written by `Fetched` — the two accounts' credential records
/// among them, the table folded from the cache alone.
#[test]
fn a_binding_typed_record_outside_the_claimants_doc_one_binds_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (registrar, org) = (signer(1), signer(2));
    let (registry, own, bound) = (a(REGISTRY), a(ORG_DOC1), a(ORG));
    let mut copy = claimed_copy(&registrar);
    copy.deposit(&registry, &commons_type(&[1]), &[bound.clone()], &enroll_text(Some(&registrar), &registry, &bound, &[(org.public_key(), true)]));
    copy.deposit(&own, t_binding(), &[bound.clone()], &binding_text(&org, &own, &[bound.clone()], &a("1.9")));
    copy.deposit(&registry, t_binding(), &[bound.clone()], &binding_text(&registrar, &registry, &[bound.clone()], &a("1.8")));
    let mut mirror = copy.rebuilt(dir.path());
    let verdict = mirror.index().standing(&a("1.8")).map(|s| s.current.verdict.clone());
    assert_eq!(verdict, Some(Verdict::Signed(fp(&registrar))), "the registrar's binding stands");
    assert_eq!(mirror.index().standing(&a("1.9")), None, "the org's binding-typed record binds nothing");
    assert_eq!(mirror.stats().binding_typed_outside_home, 1, "counted apart");
    assert!(mirror.index().suppressed().is_empty(), "and never judged: {:?}", mirror.index().suppressed());
    assert_eq!(mirror.stats().reads.total(), 0, "no wire read");
    let org_keys = mirror.current_keys(&bound).expect("read").expect("the org's table, folded from the cache");
    assert_eq!(org_keys.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>(), [fp(&org)]);
}

/// A RECORD'S POSITION AND HOME ARE ITS ROW'S (R5 (g); REG-1.10): a cache
/// line naming the registrar's binding link at another position and in an
/// org's doc 1, its atom the org's own signed binding, binds nothing — the
/// record is judged where its row puts it, in the claimant's doc 1 under the
/// registrar's table, and is UNSIGNED there, kept out at the row's position;
/// never where the line puts it, SIGNED by the org's key.
#[test]
fn a_records_position_and_home_are_its_rows_never_a_cache_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (registrar, org) = (signer(1), signer(2));
    let (registry, own, bound) = (a(REGISTRY), a(ORG_DOC1), a(ORG));
    let mut copy = claimed_copy(&registrar);
    // The courier's line: the org's own binding, kept at position 7 in the
    // org's doc 1 — while the row puts a link of that address in the
    // registrar's doc 1 at 3.
    let orgs_binding = binding_text(&org, &own, &[bound.clone()], &a("1.9"));
    let moved = StoredLink {
        at: 7,
        address: a("1.0.1.0.1.0.2.9"),
        home: own.clone(),
        ty: Some(t_binding().clone()),
        from: vec![a("1.0.2.0.1.0.1.1")],
        to: vec![bound],
    };
    copy.lines.extend(copy.kept.keep_link(moved));
    copy.lines.extend(copy.kept.keep_atom(a("1.0.2.0.1.0.1.1"), orgs_binding));
    copy.row_for(&a("1.0.1.0.1.0.2.9"), &registry);
    let mirror = copy.rebuilt(dir.path());
    assert_eq!(mirror.index().standing(&a("1.9")), None, "the org's record binds nothing");
    let kept_out: Vec<(u64, Cause)> = mirror.index().suppressed().iter().map(|s| (s.position, s.cause.clone())).collect();
    assert_eq!(kept_out, [(3, Cause::Verdict(Verdict::Unsigned))], "judged at the row's position, in the row's home");
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
    let registrar = signer(1);
    let registry = a(REGISTRY);
    let (word, wide_account) = (a("1.18446744073709551616"), a("1.0.18446744073709551616"));
    // Past the wire's digit cap, so built from its components: `a` reads
    // what a board serves, and no board serves it.
    let past_the_wire = skep_address::validate(
        Tumbler::new([Nat::from(1u8), "9".repeat(4097).parse().expect("a natural")]).expect("a tumbler"),
    )
    .expect("an address");
    let (to_org, to_wide) = ([a(ORG)], [wide_account.clone()]);
    let mut copy = claimed_copy(&registrar);
    copy.deposit(&registry, t_binding(), &to_org, &binding_text(&registrar, &registry, &to_org, &word));
    copy.deposit(&registry, t_binding(), &to_wide, &binding_text(&registrar, &registry, &to_wide, &a("1.8")));
    copy.deposit(&registry, t_binding(), &to_org, &binding_text(&registrar, &registry, &to_org, &past_the_wire));
    let mirror = copy.rebuilt(dir.path());
    assert!(mirror.index().suppressed().is_empty(), "{:?}", mirror.index().suppressed());
    let signed = Verdict::Signed(fp(&registrar));
    let past_a_word = mirror.index().standing(&word).expect("a prefix past a machine word");
    assert_eq!(past_a_word.current.verdict, signed);
    let naming = mirror.index().standing(&a("1.8")).expect("a binding naming an account past a machine word");
    assert_eq!((naming.current.verdict, naming.current.record.account), (signed.clone(), Some(wide_account)));
    let past_the_cap = mirror.index().standing(&past_the_wire).expect("a prefix past the wire's cap");
    assert_eq!(past_the_cap.current.verdict, signed);
}

/// This resolver's own resolution of a name, fixed: `org.example` at a
/// public address, every other name at none.
struct Names;

impl NameResolver for Names {
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        Ok(if host == "org.example" { vec!["93.184.216.34".parse().unwrap()] } else { Vec::new() })
    }
}

/// The verdict beside the binding at `prefix`, where the index holds one.
fn verdict_at(mirror: &Mirror, prefix: &str) -> Option<Verdict> {
    mirror.index().standing(&a(prefix)).map(|s| s.current.verdict.clone())
}

/// The fingerprints of the set that opens `account` at the head, sorted.
fn current(mirror: &mut Mirror, account: &str) -> Option<Vec<Fingerprint>> {
    mirror.current_keys(&a(account)).expect("no wire read").map(|keys| {
        let mut v: Vec<Fingerprint> = keys.iter().map(|e| Fingerprint::of(&e.key)).collect();
        v.sort_by_key(Fingerprint::to_hex);
        v
    })
}

fn sorted(signers: &[&HybridSigner]) -> Vec<Fingerprint> {
    let mut v: Vec<Fingerprint> = signers.iter().map(|s| fp(s)).collect();
    v.sort_by_key(Fingerprint::to_hex);
    v
}

/// A claimed board with one org hired: the registrar `1.0.1`'s genesis at 1
/// (an anchor and a device key), its claim at 2, the org `1.0.2`'s genesis
/// at 3 — homed in the claimant's doc 1, the device key's hand — and the
/// org's doc 1 holding its endpoint at 4, signed by the org's own key;
/// `1.5` bound to the org at 5 by the device key.
struct Fixture {
    anchor: HybridSigner,
    device: HybridSigner,
    org: HybridSigner,
    script: Script,
    org_genesis: Address,
    endpoint: Address,
}

fn fixture() -> Fixture {
    let (anchor, device, org) = (signer(1), signer(2), signer(3));
    let (registry, own, claimant, bound) = (a(REGISTRY), a(ORG_DOC1), a(CLAIMANT), a(ORG));
    let mut script = Script::new();
    script.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(None, &registry, &claimant, &[(anchor.public_key(), true), (device.public_key(), false)]));
    script.claim(&claimant);
    let org_genesis = script.deposit(&registry, &commons_type(&[1]), &[bound.clone()], &enroll_text(Some(&device), &registry, &bound, &[(org.public_key(), true)]));
    let endpoint = script.deposit(&own, t_endpoint(), &[], &endpoint_text(&org, &own, &["https://org.example"]));
    script.deposit(&registry, t_binding(), &[bound.clone()], &binding_text(&device, &registry, &[bound], &a("1.5")));
    Fixture { anchor, device, org, script, org_genesis, endpoint }
}

/// THE FORGED ROTATION (REG-5.9; REG-3.39, REG-2.33): the party that runs
/// the board plants a key into the claimant's doc 1 past the write path — an
/// enroll record with no `sig`, and one self-signed by the key it enrolls,
/// which no table holds — and serves `key_set` with the plant among the
/// claimant's keys; a binding the planted key signs is judged UNSIGNED and
/// suppressed, the plant enters no table at this reader, and the board was
/// never asked for a key set. A reader taking the board's `key_set` would
/// have called that binding SIGNED.
#[test]
fn a_rotation_the_board_planted_past_the_write_path_enrolls_no_key_at_this_reader() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Fixture { anchor, device, org, mut script, .. } = fixture();
    let (registry, claimant) = (a(REGISTRY), a(CLAIMANT));
    let (plant, plant_two) = (signer(9), signer(8));
    script.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(None, &registry, &claimant, &[(plant.public_key(), true)]));
    script.deposit(&registry, t_binding(), &[a("1.0.3")], &binding_text(&plant, &registry, &[a("1.0.3")], &a("1.6")));
    script.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(Some(&plant_two), &registry, &claimant, &[(plant_two.public_key(), true)]));
    script.deposit(&registry, t_binding(), &[a("1.0.4")], &binding_text(&plant_two, &registry, &[a("1.0.4")], &a("1.7")));
    let served = vec![anchor.public_key().clone(), device.public_key().clone(), plant.public_key().clone(), plant_two.public_key().clone()];
    let board = Rc::new(script.board(KeySetArm::Served(served)));
    let mut mirror = over_hint(board.clone(), dir.path(), &hint_of(realm_of(&[anchor.public_key(), device.public_key()])));
    assert_eq!(mirror.sync(), Ok(9));
    assert_eq!(verdict_at(&mirror, "1.5"), Some(Verdict::Signed(fp(&device))), "the registrar's own binding stands");
    assert_eq!(verdict_at(&mirror, "1.6"), None, "the sig-less plant's binding binds nothing");
    assert_eq!(verdict_at(&mirror, "1.7"), None, "the self-signed plant's binding binds nothing");
    let kept_out: Vec<Cause> = mirror.index().suppressed().iter().map(|s| s.cause.clone()).collect();
    assert_eq!(kept_out, [Cause::Verdict(Verdict::Unsigned), Cause::Verdict(Verdict::Unsigned)], "UNSIGNED, never undeterminable");
    assert_eq!(current(&mut mirror, CLAIMANT), Some(sorted(&[&anchor, &device])), "no plant in the claimant's table");
    assert_eq!(current(&mut mirror, ORG), Some(sorted(&[&org])));
    let s = mirror.stats();
    assert_eq!(s.reads.key_set, 0, "the board's key set was never asked");
    assert_eq!((s.credential_records, s.records), (4, 4), "the genesis, the hire and the two plants; the binding, the endpoint and the two forged bindings");
    assert!(s.credential_verifies >= 2, "the hire's and the self-signed plant's sigs were tried: {}", s.credential_verifies);
}

/// A GENUINE ROTATION (REG-1.86 (e); the signed-ops design record §4.5's
/// clause (b)): the registrar enrolls a third key by its device key's hand
/// and retires the device key by the new key's; a binding the device key
/// signed before its retirement is SIGNED, one it signed after is UNSIGNED,
/// one the new key signs is SIGNED, and the walk's current keys are the
/// anchor and the new key alone.
#[test]
fn a_genuine_rotation_judges_each_record_as_of_its_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Fixture { anchor, device, mut script, .. } = fixture();
    let (registry, claimant) = (a(REGISTRY), a(CLAIMANT));
    let third = signer(4);
    script.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(Some(&device), &registry, &claimant, &[(third.public_key(), false)]));
    script.deposit(&registry, t_binding(), &[a("1.0.3")], &binding_text(&device, &registry, &[a("1.0.3")], &a("1.6")));
    script.deposit(&registry, &commons_type(&[2]), &[claimant.clone()], &retire_text(&third, &registry, &claimant, &[fp(&device)]));
    script.deposit(&registry, t_binding(), &[a("1.0.4")], &binding_text(&device, &registry, &[a("1.0.4")], &a("1.7")));
    script.deposit(&registry, t_binding(), &[a("1.0.5")], &binding_text(&third, &registry, &[a("1.0.5")], &a("1.8")));
    let board = Rc::new(script.board(KeySetArm::Refused));
    let mut mirror = over_hint(board, dir.path(), &hint_of(realm_of(&[anchor.public_key(), device.public_key()])));
    assert_eq!(mirror.sync(), Ok(10));
    assert_eq!(verdict_at(&mirror, "1.5"), Some(Verdict::Signed(fp(&device))));
    assert_eq!(verdict_at(&mirror, "1.6"), Some(Verdict::Signed(fp(&device))), "signed before the retirement");
    assert_eq!(verdict_at(&mirror, "1.7"), None, "signed by the retired key after it");
    assert_eq!(verdict_at(&mirror, "1.8"), Some(Verdict::Signed(fp(&third))), "signed by the new key");
    let kept_out: Vec<(u64, Cause)> = mirror.index().suppressed().iter().map(|s| (s.position, s.cause.clone())).collect();
    assert_eq!(kept_out, [(9, Cause::Verdict(Verdict::Unsigned))]);
    assert_eq!(current(&mut mirror, CLAIMANT), Some(sorted(&[&anchor, &third])), "the device key retired");
}

/// NO BOARD KEY READ (REG-3.39): over a board that refuses `key_set` on
/// `/op` and `/op-at` alike — a read it answers with a panic — a full sync
/// and a resolve pass: the binding and the endpoint SIGNED, the walk's face
/// BOUND with the org's key set off the table, and no `key_set` counted.
#[test]
fn a_mirror_asks_the_board_for_no_key_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Fixture { anchor, device, org, script, endpoint, .. } = fixture();
    let board = Rc::new(script.board(KeySetArm::Refused));
    let mut mirror = over_hint(board.clone(), dir.path(), &hint_of(realm_of(&[anchor.public_key(), device.public_key()])));
    assert_eq!(mirror.sync(), Ok(5));
    assert!(mirror.index().suppressed().is_empty(), "{:?}", mirror.index().suppressed());
    match resolve(&mut mirror, &a("1.5"), &Names, &Transports::default()).expect("resolved") {
        crate::state::Resolution::Bound { standing, keys, endpoint: current_endpoint, dial, .. } => {
            assert_eq!(standing.current.verdict, Verdict::Signed(fp(&device)));
            assert_eq!(keys.map(|k| k.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>()), Some(vec![fp(&org)]), "the org's set off the table");
            assert_eq!((current_endpoint.link, current_endpoint.verdict), (endpoint, Verdict::Signed(fp(&org))));
            assert_eq!(dial.origin.as_str(), "https://org.example");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(mirror.stats().reads.key_set, 0);
    assert!(board.asked.borrow().iter().all(|r| !r.ends_with(" key_set")), "{:?}", board.asked.borrow());
}

/// UNDETERMINABLE HERE (the signed-ops design record §7.2's REFUSE
/// disposition): a credential record the transport will not serve — the
/// org's genesis — makes the org's table undeterminable from that position:
/// its endpoint, judged under the set that opens the org's doc 1, is
/// UNDETERMINABLE HERE and never UNSIGNED, the walk answers no key set for
/// it, and the registrar's binding — under the claimant's table, which the
/// gap does not touch — stands SIGNED.
#[test]
fn a_credential_record_the_board_will_not_serve_leaves_its_account_undeterminable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Fixture { anchor, device, script, org_genesis, endpoint, .. } = fixture();
    let board = Rc::new(script.board(KeySetArm::Refused));
    let atom = a("1.0.1.0.1.0.1.2");
    board.withhold(&atom);
    let mut mirror = over_hint(board.clone(), dir.path(), &hint_of(realm_of(&[anchor.public_key(), device.public_key()])));
    assert_eq!(mirror.sync(), Ok(5));
    assert_eq!(verdict_at(&mirror, "1.5"), Some(Verdict::Signed(fp(&device))), "the claimant's table is whole");
    let kept_out: Vec<(Address, Cause)> = mirror.index().suppressed().iter().map(|s| (s.link.clone(), s.cause.clone())).collect();
    assert_eq!(kept_out, [(endpoint, Cause::Verdict(Verdict::UndeterminableHere))], "never UNSIGNED: {org_genesis}");
    assert_eq!(current(&mut mirror, ORG), None, "the org's set is undeterminable here");
    assert_eq!(current(&mut mirror, CLAIMANT), Some(sorted(&[&anchor, &device])));
    assert_eq!(mirror.stats().credential_records, 1, "the genesis alone reached the table");
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

/// A BOARD WHERE A FORGED RETRACTION STANDS: an account's own link in its
/// own doc 1, typed `1.1.0.1.0.1.0.1` — a prefix of the retraction class's
/// address, another class `make_link` admits — and naming the node, so it
/// overlaps every link of the retraction's type and target a query asks
/// for, and such a query answers it. The board's active view, asked for
/// the deposit by its home, its type and its atom, answers `active`. Every
/// query asked is kept.
struct ActiveView {
    active: Value,
    asked: RefCell<Vec<Value>>,
}

impl Transport for ActiveView {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        assert_eq!((method, path), (Method::Post, "/op"));
        let frame: Value = serde_json::from_slice(body).expect("a frame");
        assert_eq!(frame["op"], "find_links_ftt", "a read this board does not answer: {frame}");
        self.asked.borrow_mut().push(frame["q"].clone());
        if frame["q"]["ty"][0]["start"] == "1.1.0.1.0.1.0.1.5" {
            return answer(json!({ "resp": "addrs", "addrs": ["1.0.9.0.1.0.2.1"] }));
        }
        answer(self.active.clone())
    }
}

/// A RETRACTION IS THE BOARD'S OWN READING (REG-1.11): a deposit leaves the
/// active view where the board's active links of its home, its type and its
/// atom answer it no longer — the org's own `nullify` — and never where a
/// link of the retraction's type is found, which any account's link of
/// another class overlaps; a refusal takes nothing off the view. A deposit
/// found off the view is kept at the `nullify`'s row, a standing one never.
#[test]
fn a_link_of_another_class_takes_no_deposit_off_the_view() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (deposit, home, atom) = (a("1.0.2.0.1.0.2.1"), a("1.0.2.0.1"), a("1.0.2.0.1.0.1.1"));
    let stored = StoredLink { at: 7, address: deposit.clone(), home: home.clone(), ty: Some(t_endpoint().clone()), from: vec![atom.clone()], to: Vec::new() };
    let asked = |active: Value| {
        let board = Rc::new(ActiveView { active, asked: RefCell::new(Vec::new()) });
        let mut mirror = over(board.clone(), dir.path());
        mirror.fetched.keep_link(stored.clone());
        let retracted = mirror.retracted(8, &deposit, &home).expect("answered");
        let queries = board.asked.borrow().clone();
        (retracted, queries, mirror.fetched.retracted)
    };
    let (retracted, queries, kept) = asked(json!({ "resp": "addrs", "addrs": [deposit.to_string()] }));
    assert!(!retracted, "the forged link takes nothing off the view");
    let active = json!({ "home": [unit_span_json(&home)], "from": [unit_span_json(&atom)], "to": "any", "ty": [unit_span_json(t_endpoint())] });
    assert_eq!(queries, [active], "the active view asked, never the retraction's type");
    assert!(kept.is_empty(), "a standing deposit is kept as no retraction");
    let (retracted, _, kept) = asked(json!({ "resp": "addrs", "addrs": [] }));
    assert!(retracted, "the org's own nullify: off the view");
    assert_eq!(kept.get(&8), Some(&vec![deposit.clone()]), "kept at the nullify's row");
    let refused = json!({ "resp": "rejected", "op": "find_links_ftt", "code": "unparseable" });
    assert!(!asked(refused).0, "a refusal takes nothing off the view");
}

/// A BOARD WHOSE ACTIVE VIEW HOLDS EVERY DEPOSIT of `1.0.2.0.1`.
struct AllStanding;

impl Transport for AllStanding {
    fn exchange(&self, _: Method, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        answer(json!({ "resp": "addrs", "addrs": ["1.0.2.0.1.0.2.1", "1.0.2.0.1.0.2.2", "1.0.2.0.1.0.2.3"] }))
    }
}

/// A STANDING DEPOSIT IS ASKED ONCE A PASS: every row a pass folds was
/// held before it asks, so the active view's answer stands for the pass —
/// three `nullify` rows naming a home of three standing deposits ask three
/// times, never nine — and a later pass, its rows past the answer, asks
/// afresh. The deposits are ones the gate passes: SIGNED, each of an origin.
#[test]
fn each_standing_deposit_is_asked_once_a_pass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut mirror = over(AllStanding, dir.path());
    let home = a("1.0.2.0.1");
    let deposit = |n: u64| a(&format!("1.0.2.0.1.0.2.{n}"));
    let signed = Verdict::Signed(Fingerprint::parse_hex(&"ab".repeat(32)).unwrap());
    for n in 1..=3 {
        let atom = a(&format!("1.0.2.0.1.0.1.{n}"));
        mirror.fetched.keep_link(StoredLink { at: n, address: deposit(n), home: home.clone(), ty: Some(t_endpoint().clone()), from: vec![atom], to: Vec::new() });
        let origins = vec![format!("https://{n}.example")];
        let record = EndpointRecord { origins, replaces: (n > 1).then(|| deposit(n - 1)), honored: false, nullified: false };
        let judged = Judged { position: n, link: deposit(n), home: home.clone(), record, verdict: signed.clone() };
        assert!(mirror.index.fold_endpoint(judged), "deposit {n} honored");
    }
    mirror.rows = (10..13).map(|at| json!({ "at": at, "op": "nullify", "docs": ["1.0.2.0.1"] })).collect();
    mirror.fold_pending().expect("folded");
    assert_eq!(mirror.stats().reads.find_links, 3, "each standing deposit asked once, never once a row");
    assert_eq!(mirror.index.current_endpoint(&home).map(|d| d.link.clone()), Some(deposit(3)), "every deposit stands");
    mirror.rows.push(json!({ "at": 13, "op": "nullify", "docs": ["1.0.2.0.1"] }));
    mirror.fold_pending().expect("folded");
    assert_eq!(mirror.stats().reads.find_links, 6, "a later pass asks afresh");
}

/// A BOARD WHOSE LINK `1.0.2.0.1.0.2.7` IS OF A TYPE THE FOLD DOES NOT
/// READ: its type slot two spans, its `from` three thousand atoms.
struct Untyped;

impl Transport for Untyped {
    fn exchange(&self, _: Method, _: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let frame: Value = serde_json::from_slice(body).expect("a frame");
        assert_eq!((frame["op"].as_str(), frame["a"].as_str()), (Some("read_link"), Some("1.0.2.0.1.0.2.7")));
        let from: Vec<Value> = (1..=3_000).map(|n| span(&format!("1.0.2.0.1.0.1.{n}"))).collect();
        let ty = [unit_span_json(t_endpoint()), unit_span_json(&commons_type(&[1]))];
        answer(json!({ "resp": "link", "link": { "slots": [from, [span("1.0.2")], ty] } }))
    }
}

/// A LINK OF NO TYPE THE FOLD READS is held with no slots: none of its
/// spans is parsed, and its cache line holds its type as none and nothing
/// of its `from` or its `to`.
#[test]
fn a_link_of_no_type_the_fold_reads_is_held_with_no_slots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut mirror = over(Untyped, dir.path());
    let stored = mirror.read_link(5, &a("1.0.2.0.1.0.2.7"), &a("1.0.2.0.1")).expect("answered").expect("a link stands");
    assert_eq!((stored.ty, stored.from.len(), stored.to.len()), (None, 0, 0));
    let line = json!({ "link": { "at": 5, "address": "1.0.2.0.1.0.2.7", "home": "1.0.2.0.1", "ty": null, "from": [], "to": [] } });
    assert_eq!(mirror.pending_cache, [line], "its cache line holds no slot");
}
