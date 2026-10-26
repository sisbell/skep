//! An accepted link's original stands, superseded, proved end to end through
//! the daemon: a private link `L` accepted into a published version — its
//! public copy `L′` written into the member the shot minted, then the
//! supersession claim `C` at `L`'s own home — is NOT retracted (PUB-6.22:
//! supersession is not retraction, and `nullify` is the sole retraction
//! path). What keeps the original from being offered at a later publication
//! is the publish list's FILTER, keyed three ways: an active claim of the
//! owner's naming a public successor that is (i) homed in a published
//! document of theirs, (ii) still active — `discoverable_from {a: new, d:
//! D}`, read at the DRAFT whose publication the filter admits (G1's re-key,
//! 2026-10-25: `D` is private, so nothing floats, and key (iii) already has
//! `D` arranging the copy's end, so the read answers the copy's active state
//! alone) — and (iii) standing on the spans this publication publishes.
//! Retracting the copy makes the original offerable again; putting the words
//! back from the member's identity does not; and a second
//! claim on one original is admitted (the claim's key is `(old, new)`). The
//! accept reaches no other arrangement of the words, where the retraction it
//! replaces reaches every one (PUB-6.20; R16; `member_home.rs` M8). Two
//! publications of one owner take one copy where the first's claim lands
//! before the second's read, and two where both read first (ML0: `make_link`
//! dedups nothing). The feed shows two commits per accepted link and no
//! retraction.
//!
//! wire.md §Links (writes) states `make_link`, `assert_sup` and `nullify`;
//! §Links (raw reads) `read_link`'s verbatim answer; §Link discovery reads
//! `find_links_v` ("the active links whose endsets touch the region"),
//! `discoverable_from` ("arrangement-reachable AND active") and the lineage
//! pair; §The read predicate the result-set filter at the claim's home
//! (PUB-6.13); §The change feed the rows a link write leaves; §Arrangement
//! `delete` and `reinstate`; §The publish shot and head-float the shot.
//!
//! The store and the index each hold their half in their own tests
//! (`skep-links`' `nullify.rs`: a nullified endpoint leaves its edges
//! operative; `skep-discovery`'s `lineage.rs`: a live claim can name a
//! nullified link); nothing had driven the accept's pair through the daemon
//! and asked the filter. This suite proves and fixes nothing: a case red
//! against the daemon as built is kept, ignored with the verdict met, and
//! reported.
//!
//! THE BOARD, one per test (`spawn`, CLAIMED-PERMISSIVE; the claimant
//! `1.0.1`, a signed session S, the claimant's own bare session for its draft
//! writes, and the GUEST for the class that cannot read the claimant's drafts
//! — the claimant's bare session shares the claimant's class and reads them).
//! `E` is the claimant's second document, a published edition holding a
//! passage P; shot 1 → `E.1` and shot 2 → `E.2`, each re-supplying P by
//! reference, so P's bytes are ONE identity at `E`, `E.1` and `E.2`. `N` is
//! a private notes document holding the note Z; `L`, homed in `N`, cites P on
//! `E.2` FROM and Z TO. `D` is a private draft with its own new words W and a
//! one-sided link `M` on them; `F` a private draft that transcludes P from
//! `E` by `copy`. THE ACCEPT of an original into a member: S's `make_link`
//! homed in the member, its ends V-specs the member and the far document
//! resolve, attested → the copy; `read_link` of the copy; S's `assert_sup`
//! homed where the original is → the claim. No `nullify`.
//!
//! THE FILTER (`offered`): design §5.1's reads — one `find_links_v` over the
//! selection; each address read for its home and kept where the home is a
//! private document of the claimant's (a published home is no row: the
//! destination's own chain, and the claimant's doc 1, whose two ceremony
//! records `find_links_v` answers ahead of every region's own); one
//! `in_claims {y, view: "active"}` per candidate; each claim read for its
//! `new`, whose liveness is read at the draft (`discoverable_from {new, D}`);
//! the candidate dropped where some claim's `new` meets all three keys.
//! Every address is asserted exactly, never by presence alone. R9–R11 are
//! the G1 cases the ruling owes this suite: the put-back, the daughter, and
//! the resume's liveness read at the member rather than at a bare set.

use std::collections::BTreeSet;

use crate::common;

use common::*;
use serde_json::{json, Value};

/// The citation type, a seeded commons type (`3.13`), named in the address
/// form: the one type every link here carries.
const T_CITATION: &str = "1.1.0.1.0.1.0.3.13";

/// The passages, per-byte: P the edition's standing text, Q a second passage
/// beside it, Z the note, W the draft's new words.
const P: &str = "the quick brown fox jumps over the lazy dog";
const Q: &str = "and a second passage after it";
const Z: &str = "a note on the fox and the dog";
const W: &str = "new words of the draft";
const P_LEN: u64 = P.len() as u64;
const Q_LEN: u64 = Q.len() as u64;
const Z_LEN: u64 = Z.len() as u64;
const W_LEN: u64 = W.len() as u64;

/// The empty address-form slot — a one-sided link's TO.
const NONE: &str = r#"{"addrs":[]}"#;

/// The claim ceremony's two links in the claimant's doc 1 — the genesis
/// deposit, whose TO names the account `1.0.1`, and the claim, whose FROM
/// does. An address-form slot naming an account is the unit span over it,
/// which covers every content address beneath, so `find_links_v` over any
/// region of the claimant's own documents answers the two ahead of the
/// region's own links: the floor every content read of this account has.
const CEREMONY_LINKS: [&str; 2] = ["1.0.1.0.1.0.2.1", "1.0.1.0.1.0.2.2"];

/// `addrs` in address order — the order `find_links_v` answers: each
/// component compared as a number, an address ahead of what extends it.
fn in_address_order(mut addrs: Vec<String>) -> Vec<String> {
    let key = |a: &str| -> Vec<u64> { a.split('.').map(|c| c.parse().expect("a component")).collect() };
    addrs.sort_by_key(|a| key(a));
    addrs
}

/// The ceremony's floor, then `links` in address order: `find_links_v`'s
/// whole answer over a region of the claimant's holding exactly `links`.
fn floor_and(links: &[&str]) -> Vec<String> {
    let rest = in_address_order(links.iter().map(|a| a.to_string()).collect());
    CEREMONY_LINKS.iter().map(|a| a.to_string()).chain(rest).collect()
}

/// The claimant's document `E` and its first two trunk members.
struct Chain {
    e: String,
    e1: String,
    e2: String,
}

/// P's one I-run under `E`'s own content chain — what every arrangement that
/// holds P images, and what a V-spec over P resolves to.
fn p_run(e: &str) -> (String, u64) {
    (format!("{e}.0.1.1"), P_LEN)
}

/// An I-span as a stored slot spells it: the run's start, the count in the
/// width's last component.
fn i_slot(start: &str, width: u64) -> Value {
    let zeros = start.split('.').count() - 1;
    json!([{"start": start, "width": format!("{}{width}", "0.".repeat(zeros))}])
}

/// A citation link homed in `home` FROM `from` TO `to`, each slot JSON.
fn citation(home: &str, from: &str, to: &str) -> String {
    link_frame(home, from, to, &addrs_slot(&[T_CITATION]))
}

/// The board's chain: `E` holding P, `E.1` and `E.2` holding it by reference.
fn chain(port: u16, signed: &str) -> Chain {
    let e = edition_with(port, signed, P);
    assert_eq!(e, "1.0.1.0.2", "the claimant's second document");
    let e1 = shot(port, signed, &e, Some((&e, P_LEN)), None, &shot_runs(port, None, &e, 1, P_LEN));
    assert_eq!(e1, format!("{e}.1"));
    let e2 = shot(port, signed, &e, Some((&e1, P_LEN)), None, &shot_runs(port, None, &e1, 1, P_LEN));
    assert_eq!(e2, format!("{e}.2"));
    // P's bytes are ONE identity at E.1, at E.2 and at the bare E, which
    // floats to E.2 (PUB-2.49).
    for d in [e1.as_str(), e2.as_str(), e.as_str()] {
        assert_eq!(image_runs(port, None, d, 1, P_LEN), vec![p_run(&e)], "P at {d}");
        assert_eq!(text_of(port, None, d, 1, P_LEN), P, "P's text at {d}");
    }
    Chain { e, e1, e2 }
}

/// The notes document `N` holding Z, and the original `L` homed in it: FROM
/// P's V-spec on `E.2`, TO Z's V-spec on `N`. Answers `(N, L)`.
fn notes_and_original(port: u16, bare: &str, c: &Chain) -> (String, String) {
    let n = draft_with(port, bare, Z);
    assert_eq!(n, "1.0.1.0.3", "the notes, the claimant's third document");
    let l = acked_addr(&op(port, Some(bare), &citation(&n, &vspec(&c.e2, 1, P_LEN), &vspec(&n, 1, Z_LEN))));
    assert_eq!(l, format!("{n}.0.2.1"), "the original, N's first link");
    assert_eq!(
        read_link(port, Some(bare), &l)["slots"],
        json!([i_slot(&p_run(&c.e).0, P_LEN), i_slot(&format!("{n}.0.1.1"), Z_LEN), i_slot(T_CITATION, 1)]),
        "the original's slots as stored: P's and Z's I-spans, the type"
    );
    (n, l)
}

/// A shot staged off `E.1` once `E.2` exists: `E.1`'s daughter `E.1.1`, in
/// the nested form (PUB-2.55), holding P by reference.
fn daughter(port: u16, signed: &str, c: &Chain) -> String {
    let runs = shot_runs(port, None, &c.e1, 1, P_LEN);
    let d = shot(port, signed, &c.e, Some((&c.e1, P_LEN)), None, &runs);
    assert_eq!(d, format!("{}.1", c.e1));
    assert_eq!(image_runs(port, None, &d, 1, P_LEN), vec![p_run(&c.e)]);
    d
}

/// What the accept wrote: the copy, its claim, the two acks' positions and
/// the copy as it read back.
struct Accept {
    copy: String,
    claim: String,
    copy_at: u64,
    claim_at: u64,
    copy_link: Value,
}

/// THE ACCEPT of `original`, homed in `home`, into `member` (design §5.3's
/// pair): S's attested `make_link` homed in the member, FROM and TO as given,
/// the citation type → the copy; `read_link` of the copy; S's `assert_sup`
/// homed in `home`, `old` the original, `new` the copy → the claim. No
/// `nullify`: the original is left standing.
fn accept(port: u16, signed: &str, member: &str, home: &str, original: &str, from: &str, to: &str) -> Accept {
    let v = op(port, Some(signed), &citation(member, from, to));
    assert_eq!(verdict(&v), "ok", "the copy: {v}");
    let copy = acked_addr(&v);
    let copy_at = acked_at(&v);
    let copy_link = read_link(port, Some(signed), &copy);
    assert_eq!(copy_link["slots"].as_array().map(Vec::len), Some(3), "the read-back: {copy_link}");
    let v = op(port, Some(signed), &assert_sup_frame(home, original, &copy));
    assert_eq!(verdict(&v), "ok", "the claim: {v}");
    Accept { copy, claim: acked_addr(&v), copy_at, claim_at: acked_at(&v), copy_link }
}

/// The document a link's address is homed in: the address above its `.0.2.n`.
fn home_of(link: &str) -> String {
    let idx = link.rfind(".0.2.").unwrap_or_else(|| panic!("{link} is not a link address"));
    link[..idx].to_string()
}

/// A stored slot's spans as `(start, count)` runs.
fn slot_runs(slot: &Value) -> Vec<(String, u64)> {
    slot.as_array()
        .expect("a slot")
        .iter()
        .map(|s| {
            let start = s["start"].as_str().expect("start").to_string();
            let width = s["width"].as_str().expect("width");
            let count = width.rsplit('.').next().expect("a width").parse().expect("a count");
            (start, count)
        })
        .collect()
}

/// Every address `runs` cover.
fn addresses(runs: &[(String, u64)]) -> BTreeSet<String> {
    expand_runs(runs).into_iter().collect()
}

/// The claims whose `old` is `y`, under `view`, as `token`: the rows whole.
fn claim_rows(port: u16, token: Option<&str>, y: &str, view: &str) -> Vec<Value> {
    let v = op(port, token, &format!(r#"{{"op":"in_claims","view":"{view}","y":"{y}"}}"#));
    expect_resp(&v, "claims")["claims"].as_array().expect("claims").clone()
}

/// A claim's row as `in_claims` answers it.
fn claim_row(claim: &str, home: &str, old: &str, new: &str) -> Value {
    json!({"active": true, "claim": claim, "home": home, "new": new, "old": old})
}

/// `doc`'s `(owner, published)` off `doc_metadata`, as `token`; a member
/// answers its document's.
fn owner_and_state(port: u16, token: Option<&str>, doc: &str) -> (String, bool) {
    let v = doc_metadata(port, token, doc);
    let m = expect_resp(&v, "doc_metadata");
    (m["owner"].as_str().expect("owner").to_string(), m["published"].as_bool().expect("published"))
}

/// One successor an active claim of the candidate's names, with the three
/// keys read for it.
#[derive(Debug, PartialEq, Eq)]
struct Successor {
    claim: String,
    new: String,
    /// (i) `new`'s home is a published document of the claimant's.
    published_home: bool,
    /// (ii) `new` is arrangement-reachable and active from the DRAFT being
    /// published — `d: D`, G1's re-key: read where nothing floats.
    active: bool,
    /// (iii) `new`'s FROM covers the candidate's I-runs on the selection.
    covers: bool,
}

impl Successor {
    /// Whether this successor drops its original from the list: all three.
    fn drops(&self) -> bool {
        self.published_home && self.active && self.covers
    }
}

/// A candidate of the enumeration — an active link homed in a private
/// document of the claimant's, touching the selection — and the successors
/// its active claims name.
#[derive(Debug, PartialEq, Eq)]
struct Candidate {
    link: String,
    successors: Vec<Successor>,
}

/// THE ENUMERATION (design §5.1) over the selection — content ordinals
/// `from ..` of `doc`, the draft whose publication is being prepared — read
/// as `token`: `find_links_v` over the selection; each address read for its
/// home, kept where the home is a private document of the claimant's; one
/// `in_claims {y, view: "active"}` per candidate; each claim read for its
/// `new`, and `new` read for its home, its activity from `doc` itself
/// (G1's key (ii), `discoverable_from {a: new, d: D}` — never from the
/// destination, whose bare address floats to its trunk head) and its FROM
/// slot.
fn candidates(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<Candidate> {
    let selection = addresses(&image_runs(port, token, doc, from, width));
    let mut out = Vec::new();
    for link in find_links_v(port, token, doc, from, width) {
        let (owner, published) = owner_and_state(port, token, &home_of(&link));
        if owner != CLAIMANT_ACCOUNT || published {
            continue;
        }
        let value = read_link(port, token, &link);
        let slots = value["slots"].as_array().expect("slots");
        let mut ends = addresses(&slot_runs(&slots[0]));
        ends.extend(addresses(&slot_runs(&slots[1])));
        let on_selection: BTreeSet<String> = ends.intersection(&selection).cloned().collect();
        let successors = claim_rows(port, token, &link, "active")
            .iter()
            .map(|row| {
                let claim = row["claim"].as_str().expect("claim").to_string();
                let claim_value = read_link(port, token, &claim);
                let new = claim_value["slots"][1][0]["start"].as_str().expect("the claim's new").to_string();
                assert_eq!(row["new"].as_str(), Some(new.as_str()), "the row's new is the claim's TO: {row}");
                let (new_owner, new_published) = owner_and_state(port, token, &home_of(&new));
                let active = discoverable_from(port, token, &new, doc);
                let from_end = addresses(&slot_runs(&read_link(port, token, &new)["slots"][0]));
                Successor {
                    claim,
                    new,
                    published_home: new_owner == CLAIMANT_ACCOUNT && new_published,
                    active,
                    covers: !on_selection.is_empty() && on_selection.is_subset(&from_end),
                }
            })
            .collect();
        out.push(Candidate { link, successors });
    }
    out
}

/// THE FILTER (the ruling's first rider): the candidates of
/// [`candidates`] less every one some successor drops on all three keys —
/// what the publish list offers.
fn offered(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    candidates(port, token, doc, from, width)
        .into_iter()
        .filter(|c| !c.successors.iter().any(Successor::drops))
        .map(|c| c.link)
        .collect()
}

/// The CONTRAST: a filter keyed on (i) alone — "a public link of the
/// person's" — which drops an original whose copy was since retracted.
fn offered_by_publication_alone(
    port: u16,
    token: Option<&str>,
    doc: &str,
    from: u64,
    width: u64,
) -> Vec<String> {
    candidates(port, token, doc, from, width)
        .into_iter()
        .filter(|c| !c.successors.iter().any(|s| s.published_home))
        .map(|c| c.link)
        .collect()
}

/// The change-feed entries past `since`, as `token` (`None` = the guest).
fn changes_since(port: u16, token: Option<&str>, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), token, b"");
    assert_eq!(st, 200, "/changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// R1 — the original stands beside its copy (PUB-6.22; the ruling): after
/// the accept, `read_link L` answers verbatim and `L` is still discoverable
/// from `E`; `find_links_v` over P at `E.2` answers `L` and `L′` for S and
/// `L′` alone for the guest, the census the floor's two plus each; at `N`
/// over Z both end there; `in_claims {y: L}` answers `C` and `out_claims {x:
/// L′}` answers `C` for S, and the guest no row (the claim's home
/// unreadable, PUB-6.13).
#[test]
fn the_accepted_original_stands_beside_its_copy_superseded_and_unretracted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed);
    let (n, l) = notes_and_original(port, &bare, &c);
    let Chain { e, e2, .. } = &c;
    let before = read_link(port, Some(&signed), &l);
    assert_eq!(find_links_v(port, Some(&signed), e2, 1, P_LEN), floor_and(&[&l]), "before: the owner at E.2");
    assert_eq!(find_links_v(port, None, e2, 1, P_LEN), floor_and(&[]), "before: the guest sees no private link");

    let a = accept(port, &signed, e2, &n, &l, &vspec(e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(a.copy, format!("{e2}.0.2.1"), "the copy, the member's first link");
    assert_eq!(a.claim, format!("{n}.0.2.2"), "the claim, N's next link");
    assert_eq!(
        a.copy_link["slots"],
        json!([i_slot(&p_run(e).0, P_LEN), i_slot(&format!("{n}.0.1.1"), Z_LEN), i_slot(T_CITATION, 1)]),
        "the copy's slots: P's and Z's I-spans, the type"
    );

    assert_eq!(read_link(port, Some(&signed), &l), before, "the original reads back verbatim");
    assert!(read_link(port, None, &l).is_null(), "the guest: the original is absent by address");
    assert!(discoverable_from(port, Some(&signed), &l, e), "the original is active and reachable from E");
    assert!(discoverable_from(port, Some(&signed), &a.copy, e), "and so is its copy");
    assert_eq!(find_links_v(port, Some(&signed), e2, 1, P_LEN), floor_and(&[&a.copy, &l]), "the owner at E.2: both");
    assert_eq!(find_links_v(port, None, e2, 1, P_LEN), floor_and(&[&a.copy]), "the guest at E.2: the copy alone");
    assert_eq!(count_v(port, Some(&signed), e2, 1, P_LEN), 4, "the owner's census: the floor's two and the pair");
    assert_eq!(count_v(port, None, e2, 1, P_LEN), 3, "the guest's census: the floor's two and the copy");
    assert_eq!(find_links_v(port, Some(&signed), &n, 1, Z_LEN), floor_and(&[&a.copy, &l]), "at N over Z: both end there");
    assert_eq!(
        claim_rows(port, Some(&signed), &l, "active"),
        vec![claim_row(&a.claim, &n, &l, &a.copy)],
        "the original's one active claim"
    );
    assert_eq!(claims_out(port, Some(&signed), &a.copy, "active"), vec![a.claim.clone()], "the copy's one claim");
    assert_eq!(claim_rows(port, None, &l, "active"), Vec::<Value>::new(), "the guest: the claim's home unreadable");
    assert_eq!(claims_out(port, None, &a.copy, "active"), Vec::<String>::new(), "the guest: no row");
    sd.shutdown();
}

/// R2 — the filter drops it (the ruling's first rider): before the accept
/// `offered` over P at `E.2` answers `L`; after it the one candidate's one
/// successor meets all three keys and `offered` answers nothing; a second
/// private link `L2` in `N` on P with no claim IS offered; and `L′` is never
/// a candidate — its home is the member, which projects to the published
/// `E` ("`E` no row").
#[test]
fn the_filter_drops_the_accepted_original_on_all_three_keys_and_offers_an_unclaimed_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed);
    let (n, l) = notes_and_original(port, &bare, &c);
    let Chain { e, e2, .. } = &c;
    assert_eq!(offered(port, Some(&signed), e2, 1, P_LEN), vec![l.clone()], "before the accept: offered");

    let a = accept(port, &signed, e2, &n, &l, &vspec(e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(
        candidates(port, Some(&signed), e2, 1, P_LEN),
        vec![Candidate {
            link: l.clone(),
            successors: vec![Successor {
                claim: a.claim.clone(),
                new: a.copy.clone(),
                published_home: true,
                active: true,
                covers: true,
            }],
        }],
        "one candidate, its one successor meeting all three keys"
    );
    assert_eq!(offered(port, Some(&signed), e2, 1, P_LEN), Vec::<String>::new(), "the accepted original: offered no more");
    assert_eq!(owner_and_state(port, None, &home_of(&a.copy)), (CLAIMANT_ACCOUNT.to_string(), true), "the copy's home is published");
    assert_eq!(
        expect_resp(&doc_metadata(port, None, e2), "doc_metadata")["doc"].as_str(),
        Some(e.as_str()),
        "the member projects to E: no row"
    );

    let l2 = acked_addr(&op(port, Some(&bare), &citation(&n, &vspec(e2, 1, P_LEN), &vspec(&n, 1, Z_LEN))));
    assert_eq!(l2, format!("{n}.0.2.3"), "N's third link, past the claim");
    assert_eq!(find_links_v(port, Some(&signed), e2, 1, P_LEN), floor_and(&[&a.copy, &l, &l2]), "the owner at E.2");
    assert_eq!(
        candidates(port, Some(&signed), e2, 1, P_LEN)
            .iter()
            .map(|c| (c.link.clone(), c.successors.len()))
            .collect::<Vec<_>>(),
        vec![(l.clone(), 1), (l2.clone(), 0)],
        "two candidates: the accepted one with its claim, the new one with none"
    );
    assert_eq!(offered(port, Some(&signed), e2, 1, P_LEN), vec![l2], "the unclaimed one alone is offered");
    sd.shutdown();
}

/// R3 — the copy retracted, the original offered again (the second rider;
/// `nullify.rs`: a nullified endpoint leaves its edges operative;
/// `lineage.rs`: resident, not active): S's `nullify {home: E.2, target: L′}`
/// is acked with the member's next address; `in_claims {y: L}` STILL answers
/// `C`, active; `discoverable_from {a: L′, d: E}` is false; `find_links_v`
/// over P at `E.2` answers `L` alone for S and nothing for the guest; the
/// filter offers `L` again, key (ii) failing — where the contrast keyed on
/// (i) alone would drop it for good.
#[test]
fn retracting_the_copy_leaves_its_claim_active_and_offers_the_original_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed);
    let (n, l) = notes_and_original(port, &bare, &c);
    let Chain { e, e2, .. } = &c;
    let a = accept(port, &signed, e2, &n, &l, &vspec(e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(offered(port, Some(&signed), e2, 1, P_LEN), Vec::<String>::new(), "accepted: not offered");

    let v = op(port, Some(&signed), &nullify_frame(e2, &a.copy));
    assert_eq!(verdict(&v), "ok", "{v}");
    let retraction = acked_addr(&v);
    assert_eq!(retraction, format!("{e2}.0.2.2"), "the retraction, the member's next link");

    assert_eq!(
        claim_rows(port, Some(&signed), &l, "active"),
        vec![claim_row(&a.claim, &n, &l, &a.copy)],
        "the claim's activity is its own: still answered, still active"
    );
    assert!(!discoverable_from(port, Some(&signed), &a.copy, e), "the copy is retracted: not discoverable from E");
    assert!(discoverable_from(port, Some(&signed), &l, e), "the original stands");
    assert_eq!(read_link(port, None, &a.copy)["slots"].as_array().map(Vec::len), Some(3), "the copy's value stands, retracted");
    assert_eq!(find_links_v(port, Some(&signed), e2, 1, P_LEN), floor_and(&[&l]), "the owner at E.2: the original alone");
    assert_eq!(find_links_v(port, None, e2, 1, P_LEN), floor_and(&[]), "the guest at E.2: nothing");
    assert_eq!(
        candidates(port, Some(&signed), e2, 1, P_LEN),
        vec![Candidate {
            link: l.clone(),
            successors: vec![Successor {
                claim: a.claim.clone(),
                new: a.copy.clone(),
                published_home: true,
                active: false,
                covers: true,
            }],
        }],
        "the successor is public and covering, and no longer active"
    );
    assert_eq!(offered(port, Some(&signed), e2, 1, P_LEN), vec![l.clone()], "offered again: key (ii) fails");
    assert_eq!(
        offered_by_publication_alone(port, Some(&signed), e2, 1, P_LEN),
        Vec::<String>::new(),
        "the contrast: keyed on (i) alone, the original could never be published again"
    );
    sd.shutdown();
}

/// R4 — the put-back, the original offered again and claimed twice (the
/// third rider; investigation §3.5): `M` on `D`'s new words W; the shot of
/// `D` → `E.3` re-inserting W as fresh identity; the accept of `M` into `E.3`
/// → `M′`, `C_M` in `D`. On the draft's own text the copy covers nothing —
/// new words are never covered — and `M` is still a candidate; the
/// ceremony's re-window of `D` onto `E.3`'s spans (design §5.7's 5c) is what
/// takes it off the list, `M` standing on no position of the re-windowed
/// text. Then W is deleted and its draft-native I-runs reinstated, so `D`
/// arranges them again: `M` is offered ((iii) fails: `M′`'s runs are `E.3`'s
/// fresh identity, not W's); a second shot → `E.4`; the accept again → `M″`
/// and a second claim on the one original, admitted (the key is `(old,
/// new)`); `in_claims {y: M}` answers both; the re-window onto `E.4` takes
/// `M` off the list again.
#[test]
fn a_put_back_passage_offers_its_original_again_and_takes_a_second_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed);
    let Chain { e, e2, .. } = &c;
    let d = draft_with(port, &bare, W);
    assert_eq!(d, "1.0.1.0.3", "the draft, the claimant's third document");
    let w_native = (format!("{d}.0.1.1"), W_LEN);
    let m = acked_addr(&op(port, Some(&bare), &citation(&d, &vspec(&d, 1, W_LEN), NONE)));
    assert_eq!(m, format!("{d}.0.2.1"), "the one-sided link on W, D's first");
    assert_eq!(offered(port, Some(&signed), &d, 1, W_LEN), vec![m.clone()], "before any shot: offered");

    // Shot 3 off E.2: P by reference, W from the staging draft as fresh
    // identity under E's own content chain.
    let mut runs = shot_runs(port, None, e2, 1, P_LEN);
    runs.push(run(&d, &w_native.0, W_LEN));
    let e3 = shot(port, &signed, e, Some((e2, P_LEN)), Some(&d), &runs);
    assert_eq!(e3, format!("{e}.3"));
    let w_fresh_3 = (format!("{e}.0.1.{}", P_LEN + 1), W_LEN);
    assert_eq!(image_runs(port, None, &e3, P_LEN + 1, W_LEN), vec![w_fresh_3.clone()], "W re-inserted as fresh identity");
    assert_eq!(text_of(port, None, &e3, P_LEN + 1, W_LEN), W);

    let a3 = accept(port, &signed, &e3, &d, &m, &vspec(&e3, P_LEN + 1, W_LEN), NONE);
    assert_eq!(a3.copy, format!("{e3}.0.2.1"), "the copy, E.3's first link");
    assert_eq!(a3.claim, format!("{d}.0.2.2"), "the claim, D's next link");
    assert_eq!(
        a3.copy_link["slots"],
        json!([i_slot(&w_fresh_3.0, W_LEN), [], i_slot(T_CITATION, 1)]),
        "the copy's FROM: E.3's fresh spans"
    );
    assert_eq!(
        candidates(port, Some(&signed), &d, 1, W_LEN),
        vec![Candidate {
            link: m.clone(),
            successors: vec![Successor {
                claim: a3.claim.clone(),
                new: a3.copy.clone(),
                published_home: true,
                active: false,
                covers: false,
            }],
        }],
        "on the draft-native words the copy covers nothing — new words never — and reads \
         unreachable at D, which arranges W's own identity and none of E.3's"
    );
    assert_eq!(offered(port, Some(&signed), &d, 1, W_LEN), vec![m.clone()], "at D's own text, still offered");

    // THE RE-WINDOW (5c): D's text replaced by E.3's spans — the shot's
    // placed runs are what D now holds.
    expect_resp(&op(port, Some(&bare), &delete_frame(&d, 1, W_LEN)), "ack");
    expect_resp(&copy_span(port, &bare, &d, 1, &e3, P_LEN + 1, W_LEN), "ack");
    assert_eq!(image_runs(port, Some(&bare), &d, 1, W_LEN), vec![w_fresh_3.clone()], "D windows E.3's fresh spans");
    assert_eq!(
        find_links_v(port, Some(&signed), &d, 1, W_LEN),
        floor_and(&[&a3.copy]),
        "the copy by identity; M stands on no position of the re-windowed text"
    );
    assert_eq!(offered(port, Some(&signed), &d, 1, W_LEN), Vec::<String>::new(), "NOT M: no candidate");

    // THE PUT-BACK: W removed and its draft-native I-runs reinstated at
    // their own addresses, so D arranges them again.
    expect_resp(&op(port, Some(&bare), &delete_frame(&d, 1, W_LEN)), "ack");
    expect_resp(&op(port, Some(&bare), &reinstate_frame(&d, 1, &[(&d, &w_native.0, W_LEN)])), "ack");
    assert_eq!(image_runs(port, Some(&bare), &d, 1, W_LEN), vec![w_native.clone()], "the draft-native spans again");
    assert_eq!(text_of(port, Some(&bare), &d, 1, W_LEN), W);
    assert_eq!(
        find_links_v(port, Some(&signed), &d, 1, W_LEN),
        floor_and(&[&m]),
        "M is back with its words; the copy is on E.3's identity, not here"
    );
    assert_eq!(
        offered(port, Some(&signed), &d, 1, W_LEN),
        vec![m.clone()],
        "offered again: (iii) fails, the copy's runs being E.3's fresh identity, not W's"
    );

    // Shot 4 off E.3: P by reference, W from the draft as fresh identity a
    // SECOND time.
    let mut runs = shot_runs(port, None, &e3, 1, P_LEN);
    runs.push(run(&d, &w_native.0, W_LEN));
    let e4 = shot(port, &signed, e, Some((&e3, P_LEN + W_LEN)), Some(&d), &runs);
    assert_eq!(e4, format!("{e}.4"));
    let w_fresh_4 = (format!("{e}.0.1.{}", P_LEN + W_LEN + 1), W_LEN);
    assert_eq!(image_runs(port, None, &e4, P_LEN + 1, W_LEN), vec![w_fresh_4.clone()], "a second fresh identity");

    let a4 = accept(port, &signed, &e4, &d, &m, &vspec(&e4, P_LEN + 1, W_LEN), NONE);
    assert_eq!(a4.copy, format!("{e4}.0.2.1"), "the second copy, E.4's first link");
    assert_eq!(a4.claim, format!("{d}.0.2.3"), "the second claim on one original, admitted");
    assert_eq!(a4.copy_link["slots"][0], i_slot(&w_fresh_4.0, W_LEN));
    assert_eq!(
        claim_rows(port, Some(&signed), &m, "active"),
        vec![claim_row(&a3.claim, &d, &m, &a3.copy), claim_row(&a4.claim, &d, &m, &a4.copy)],
        "both claims, both active"
    );
    // The found fact G1 closed: read at `E`'s trunk HEAD (PUB-2.49, the
    // pointwise pair floats) the first copy, retracted by no one, reads as
    // not discoverable once the second shot lands — an older member's
    // new-words copy is "active" at its own member alone. Read at D, G1's
    // key, both copies answer by D's own arrangement, which holds W's native
    // identity and so neither copy's words: nothing floats.
    assert!(discoverable_from(port, Some(&signed), &a3.copy, &e3), "the first copy, at its own member");
    assert!(!discoverable_from(port, Some(&signed), &a3.copy, e), "…and no longer from E, floated to E.4");
    assert!(discoverable_from(port, Some(&signed), &a4.copy, e), "the second copy, at the head");
    assert_eq!(
        candidates(port, Some(&signed), &d, 1, W_LEN)
            .iter()
            .flat_map(|c| c.successors.iter().map(|s| (s.new.clone(), s.published_home, s.active, s.covers)))
            .collect::<Vec<_>>(),
        vec![(a3.copy.clone(), true, false, false), (a4.copy.clone(), true, false, false)],
        "on the draft-native words neither copy is reachable from D, and neither covers"
    );
    assert_eq!(offered(port, Some(&signed), &d, 1, W_LEN), vec![m.clone()], "at D's own text, still offered");

    // The re-window onto E.4 takes it off the list again.
    expect_resp(&op(port, Some(&bare), &delete_frame(&d, 1, W_LEN)), "ack");
    expect_resp(&copy_span(port, &bare, &d, 1, &e4, P_LEN + 1, W_LEN), "ack");
    assert_eq!(find_links_v(port, Some(&signed), &d, 1, W_LEN), floor_and(&[&a4.copy]), "E.4's copy alone, by identity");
    assert_eq!(offered(port, Some(&signed), &d, 1, W_LEN), Vec::<String>::new(), "NOT M");
    sd.shutdown();
}

/// R5 — the accept reaches no other arrangement (investigation §3.4; M8's
/// contrast): `F` transcludes P from `E`; `find_links_v` at `F` over P
/// answers `L` for S before the accept and `L` and `L′` after it, both on
/// P's identity. On a SECOND board the ruled retraction is driven instead —
/// `nullify {home: N, target: L}` after the claim — and `F` answers `L′`
/// alone: the loss the accept without a retraction avoids, shown beside it.
#[test]
fn the_accept_reaches_no_other_arrangement_of_the_words_where_the_retraction_reaches_every_one() {
    // The transcluding draft F, and the owner's links on P there.
    let with_f = |port: u16, signed: &str, bare: &str| -> (Chain, String, String, String) {
        let c = chain(port, signed);
        let (n, l) = notes_and_original(port, bare, &c);
        let f = owner_draft(port, bare);
        assert_eq!(f, "1.0.1.0.4", "the transcluding draft, the claimant's fourth document");
        expect_resp(&copy_span(port, bare, &f, 1, &c.e, 1, P_LEN), "ack");
        assert_eq!(image_runs(port, Some(bare), &f, 1, P_LEN), vec![p_run(&c.e)], "F holds P's identity");
        assert_eq!(find_links_v(port, Some(signed), &f, 1, P_LEN), floor_and(&[&l]), "before the accept: L at F");
        (c, n, l, f)
    };

    // Board 1: the accept, nothing retracted.
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (c, n, l, f) = with_f(port, &signed, &bare);
    let a = accept(port, &signed, &c.e2, &n, &l, &vspec(&c.e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(
        find_links_v(port, Some(&signed), &f, 1, P_LEN),
        floor_and(&[&a.copy, &l]),
        "after the accept: both at F, on P's identity"
    );
    assert_eq!(count_v(port, Some(&signed), &f, 1, P_LEN), 4);
    sd.shutdown();

    // Board 2: the ruled retraction instead.
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (c, n, l, f) = with_f(port, &signed, &bare);
    let a = accept(port, &signed, &c.e2, &n, &l, &vspec(&c.e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    let v = op(port, Some(&signed), &nullify_frame(&n, &l));
    assert_eq!(verdict(&v), "ok", "the ruled retraction: {v}");
    assert_eq!(acked_addr(&v), format!("{n}.0.2.3"), "the retraction, N's next link");
    assert_eq!(
        find_links_v(port, Some(&signed), &f, 1, P_LEN),
        floor_and(&[&a.copy]),
        "the retraction reaches the transcluding draft: the original is gone there too"
    );
    assert_eq!(count_v(port, Some(&signed), &f, 1, P_LEN), 3);
    assert!(!discoverable_from(port, Some(&signed), &l, &c.e), "retracted: not discoverable");
    assert_eq!(read_link(port, Some(&signed), &l)["slots"].as_array().map(Vec::len), Some(3), "the value stands");
    sd.shutdown();
}

/// R6 — the second publication, sequential (investigation §3.8's second
/// row): two signed sessions of the claimant under the one key; S1 accepts
/// `L` into `E.2`, link and claim; S2's `offered` over P, read AFTER S1's
/// claim stands, answers nothing — one successor — and `in_claims {y: L}`
/// answers the one claim.
#[test]
fn a_second_publication_reading_after_the_first_claim_offers_the_original_no_more() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let s1 = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let s2 = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    assert_ne!(s1, s2, "two sessions under one key");
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &s1);
    let (n, l) = notes_and_original(port, &bare, &c);
    let Chain { e2, .. } = &c;
    assert_eq!(offered(port, Some(&s2), e2, 1, P_LEN), vec![l.clone()], "before: S2 is offered L");

    let a = accept(port, &s1, e2, &n, &l, &vspec(e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(a.copy, format!("{e2}.0.2.1"));
    assert_eq!(a.claim, format!("{n}.0.2.2"));
    assert_eq!(offered(port, Some(&s2), e2, 1, P_LEN), Vec::<String>::new(), "S2, reading after S1's claim: not offered");
    assert_eq!(claim_rows(port, Some(&s2), &l, "active"), vec![claim_row(&a.claim, &n, &l, &a.copy)], "one claim");
    assert_eq!(find_links_v(port, Some(&s2), e2, 1, P_LEN), floor_and(&[&a.copy, &l]), "one successor beside the original");
    sd.shutdown();
}

/// R7 — the race, both read first (investigation §3.8's first row; ML0):
/// S1's `offered` and S2's `offered` are both read BEFORE either writes, both
/// answering `L`; S2's shot mints the daughter `E.1.1`; S1 writes `L′` into
/// `E.2` with its claim and S2 writes `L″` into `E.1.1` with its claim;
/// `in_claims {y: L}` answers TWO claims and `find_links_v` over P at `E`
/// answers `L′` and `L″` — and `L` for S. The race shown: no arm closes it.
#[test]
fn two_publications_that_both_read_first_mint_two_copies_and_two_claims() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let s1 = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let s2 = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &s1);
    let (n, l) = notes_and_original(port, &bare, &c);
    let Chain { e, e2, .. } = &c;
    assert_eq!(offered(port, Some(&s1), e2, 1, P_LEN), vec![l.clone()], "S1 reads first: offered");
    assert_eq!(offered(port, Some(&s2), e2, 1, P_LEN), vec![l.clone()], "S2 reads first: offered");

    let e11 = daughter(port, &s2, &c);
    let a1 = accept(port, &s1, e2, &n, &l, &vspec(e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    let a2 = accept(port, &s2, &e11, &n, &l, &vspec(&e11, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(a1.copy, format!("{e2}.0.2.1"), "S1's copy, E.2's first link");
    assert_eq!(a1.claim, format!("{n}.0.2.2"), "S1's claim");
    assert_eq!(a2.copy, format!("{e11}.0.2.1"), "S2's copy, the daughter's first link");
    assert_eq!(a2.claim, format!("{n}.0.2.3"), "S2's claim: a second claim on one original, admitted");
    assert_eq!(
        claim_rows(port, Some(&s1), &l, "active"),
        vec![claim_row(&a1.claim, &n, &l, &a1.copy), claim_row(&a2.claim, &n, &l, &a2.copy)],
        "two claims"
    );
    assert_eq!(
        find_links_v(port, Some(&s1), e, 1, P_LEN),
        floor_and(&[&a2.copy, &a1.copy, &l]),
        "the owner at E: two copies and the original"
    );
    assert_eq!(find_links_v(port, None, e, 1, P_LEN), floor_and(&[&a2.copy, &a1.copy]), "the guest at E: two copies");
    assert_eq!(count_v(port, None, e, 1, P_LEN), 4, "two public marks for every reader");
    assert_eq!(
        offered(port, Some(&s1), e2, 1, P_LEN),
        Vec::<String>::new(),
        "afterwards either session's filter drops the original on either claim"
    );
    sd.shutdown();
}

/// R8 — the feed (§The change feed): the `/changes` rows since the position
/// before the accept of `L` — for the guest ONE row, the `make_link` of `L′`
/// with its `attest`, naming `E.2`; for S that row and the `assert_sup` row
/// naming `[N]` and carrying the claim's address in `link` (W14: a one-home
/// row, whole or omitted, so the address never rides a reduced row); no
/// `nullify` row — two commits per accepted link.
#[test]
fn the_feed_shows_two_commits_per_accepted_link_and_no_retraction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed);
    let (n, l) = notes_and_original(port, &bare, &c);
    let Chain { e2, .. } = &c;

    let before = head_position(port);
    let a = accept(port, &signed, e2, &n, &l, &vspec(e2, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert!(a.copy_at > before && a.claim_at > a.copy_at, "two commits, in order");

    let guest = changes_since(port, None, before);
    assert_eq!(guest.len(), 1, "the guest: one row, the copy's: {guest:?}");
    let row = &guest[0];
    assert_eq!(row["at"].as_u64(), Some(a.copy_at), "{row}");
    assert_eq!(row["op"].as_str(), Some("make_link"), "{row}");
    assert_eq!(row["docs"], json!([e2]), "the row names the member as the home: {row}");
    assert_eq!(row["link"].as_str(), Some(a.copy.as_str()), "{row}");
    assert!(row.get("attest").is_some_and(|at| at["sig"].is_string()), "a signed row carries its attest: {row}");
    assert!(row.get("key").is_none(), "and no key: {row}");

    let owner = changes_since(port, Some(&signed), before);
    assert_eq!(owner.len(), 2, "the owner: two commits per accepted link: {owner:?}");
    assert_eq!(owner[0], guest[0], "the copy's row, whole to both classes");
    let claim = &owner[1];
    assert_eq!(claim["at"].as_u64(), Some(a.claim_at), "{claim}");
    assert_eq!(claim["op"].as_str(), Some("assert_sup"), "{claim}");
    assert_eq!(claim["docs"], json!([n]), "the claim's row names the original's home: {claim}");
    assert_eq!(claim["link"].as_str(), Some(a.claim.as_str()), "the claim's address rides its row (W14): {claim}");
    assert!(claim.get("attest").is_none(), "a draft-homed claim is unsigned: {claim}");
    for rows in [&guest, &owner] {
        assert!(rows.iter().all(|r| r["op"].as_str() != Some("nullify")), "no retraction: {rows:?}");
    }
    sd.shutdown();
}

/// R9 — THE PUT-BACK (G1's main fix, the first case it closed): a
/// removal-only version drops the passage and the writer puts it back in
/// the staging draft from the member's identity; the accepted original is
/// NOT offered again. `E` holds P then Q, `E.1` both by reference; `L` on P
/// is accepted into `E.1` → `L′`, `C`; shot 2 keeps Q alone, so `E.2` drops
/// P; the draft `D` then copies P back by identity from `E.1`. Key (ii) read
/// at `D` — which arranges P's identity, the words `L′` stands on — holds,
/// and `L` is dropped; read at `E`, whose head `E.2` holds no P, it failed,
/// and the original was offered again, its row switched on writing a second
/// permanent public copy on the same words (the fact G1 closed). `D` is
/// private: nothing floats.
#[test]
fn a_passage_put_back_from_the_members_identity_offers_its_accepted_original_no_more() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // E: P then Q; E.1 holds both by reference.
    let e = edition_with(port, &signed, P);
    deposit_text(port, &signed, &e, P_LEN + 1, Q);
    assert_eq!(text_of(port, None, &e, 1, P_LEN + Q_LEN), format!("{P}{Q}"));
    let e1 = shot(port, &signed, &e, Some((&e, P_LEN + Q_LEN)), None, &shot_runs(port, None, &e, 1, P_LEN + Q_LEN));
    assert_eq!(e1, format!("{e}.1"));
    let n = draft_with(port, &bare, Z);
    let l = acked_addr(&op(port, Some(&bare), &citation(&n, &vspec(&e1, 1, P_LEN), &vspec(&n, 1, Z_LEN))));
    let a = accept(port, &signed, &e1, &n, &l, &vspec(&e1, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(a.copy_link["slots"][0], i_slot(&p_run(&e).0, P_LEN), "the copy stands on P's identity");

    // The removal-only version: Q alone, by reference — E.2 drops P.
    let e2 = shot(port, &signed, &e, Some((&e1, P_LEN + Q_LEN)), None, &shot_runs(port, None, &e1, P_LEN + 1, Q_LEN));
    assert_eq!(e2, format!("{e}.2"));
    assert_eq!(text_of(port, None, &e2, 1, Q_LEN), Q, "E.2 holds Q alone");
    assert!(
        !discoverable_from(port, Some(&signed), &a.copy, &e),
        "read at E's head the copy is unreachable: the old key's failure, the original offered again"
    );

    // THE PUT-BACK: the staging draft D takes P back by identity.
    let d = owner_draft(port, &bare);
    expect_resp(&copy_span(port, &bare, &d, 1, &e1, 1, P_LEN), "ack");
    assert_eq!(image_runs(port, Some(&bare), &d, 1, P_LEN), vec![p_run(&e)], "D arranges P's identity");
    assert!(discoverable_from(port, Some(&signed), &a.copy, &d), "read at D, the copy is reachable and active");
    assert_eq!(
        candidates(port, Some(&signed), &d, 1, P_LEN),
        vec![Candidate {
            link: l.clone(),
            successors: vec![Successor {
                claim: a.claim.clone(),
                new: a.copy.clone(),
                published_home: true,
                active: true,
                covers: true,
            }],
        }],
        "the one candidate's one successor meets all three keys at D"
    );
    assert_eq!(
        offered(port, Some(&signed), &d, 1, P_LEN),
        Vec::<String>::new(),
        "the put-back passage's accepted original is NOT offered again"
    );
    sd.shutdown();
}

/// R10 — THE DAUGHTER (G1's main fix, the second case it closed — an agent's
/// parallel task landing as a daughter): staged off `E.1` once `E.2`
/// exists, the shot lands as the daughter `E.1.1`, re-inserting the draft's
/// new words W as fresh identity the trunk head NEVER holds; `M` on W and
/// `L` on P are both accepted into the daughter; the ceremony re-windows
/// `D` onto the daughter's spans (5c). Read at `E` — its head `E.2` — the
/// fresh-word copy is unreachable, forever: the old key re-offered its
/// original at every later publication from `D`, one permanent copy each.
/// Read at `D`, which arranges the daughter's words, both copies are
/// active, and nothing on the daughter's line is offered again: `L` is
/// dropped on all three keys, and `M` stands on no position of the
/// re-windowed text. (A re-inserted word's original becomes a candidate
/// again only through the shot's correspondence records — the shot lane's,
/// not built here — so this case pins the key's read.)
#[test]
fn a_daughters_accepted_originals_are_not_offered_again_on_its_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed);
    let (n, l) = notes_and_original(port, &bare, &c);
    let d = draft_with(port, &bare, W);
    let w_native = (format!("{d}.0.1.1"), W_LEN);
    let m = acked_addr(&op(port, Some(&bare), &citation(&d, &vspec(&d, 1, W_LEN), NONE)));

    // Off E.1 with E.2 standing: the daughter E.1.1 — P by reference, W fresh.
    let mut runs = shot_runs(port, None, &c.e1, 1, P_LEN);
    runs.push(run(&d, &w_native.0, W_LEN));
    let e11 = shot(port, &signed, &c.e, Some((&c.e1, P_LEN)), Some(&d), &runs);
    assert_eq!(e11, format!("{}.1", c.e1), "a daughter of E.1");
    let fresh = image_runs(port, None, &e11, P_LEN + 1, W_LEN);
    assert_eq!(fresh.len(), 1, "W re-inserted as one fresh run: {fresh:?}");
    assert_eq!(text_of(port, None, &e11, P_LEN + 1, W_LEN), W);

    // Both accepts into the daughter: M on the fresh words, L on P.
    let am = accept(port, &signed, &e11, &d, &m, &vspec(&e11, P_LEN + 1, W_LEN), NONE);
    let al = accept(port, &signed, &e11, &n, &l, &vspec(&e11, 1, P_LEN), &vspec(&n, 1, Z_LEN));
    assert_eq!(am.copy_link["slots"][0], i_slot(&fresh[0].0, W_LEN), "M′ stands on the daughter's fresh identity");
    assert_eq!(al.copy_link["slots"][0], i_slot(&p_run(&c.e).0, P_LEN), "L′ stands on P's identity");

    // The re-window (5c): D windows the daughter's spans — P and the fresh W,
    // I-adjacent under E's own content chain and so imaged as one run.
    expect_resp(&op(port, Some(&bare), &delete_frame(&d, 1, W_LEN)), "ack");
    expect_resp(&copy_span(port, &bare, &d, 1, &e11, 1, P_LEN + W_LEN), "ack");
    assert_eq!(fresh[0].0, format!("{}.0.1.{}", c.e, P_LEN + 1), "the fresh identity follows P under E's chain");
    assert_eq!(
        image_runs(port, Some(&bare), &d, 1, P_LEN + W_LEN),
        vec![(p_run(&c.e).0, P_LEN + W_LEN)],
        "D arranges P's identity and the daughter's fresh words, one I-run"
    );

    // The found fact: at E's head the fresh-word copy is unreachable,
    // forever; at its own member and at D it is active.
    assert!(!discoverable_from(port, Some(&signed), &am.copy, &c.e), "E's head never holds the daughter's words: the old key's failure");
    assert!(discoverable_from(port, Some(&signed), &am.copy, &e11), "at its own member");
    assert!(discoverable_from(port, Some(&signed), &am.copy, &d), "read at D: active");
    assert!(discoverable_from(port, Some(&signed), &al.copy, &d));

    // Nothing on the daughter's line is offered again.
    assert_eq!(
        find_links_v(port, Some(&signed), &d, 1, P_LEN + W_LEN),
        floor_and(&[&al.copy, &am.copy, &l]),
        "the two copies by identity and L on P; M stands on no position of the re-windowed text"
    );
    assert_eq!(
        candidates(port, Some(&signed), &d, 1, P_LEN + W_LEN),
        vec![Candidate {
            link: l.clone(),
            successors: vec![Successor {
                claim: al.claim.clone(),
                new: al.copy.clone(),
                published_home: true,
                active: true,
                covers: true,
            }],
        }],
        "L's successor in the daughter meets all three keys at D"
    );
    assert_eq!(
        offered(port, Some(&signed), &d, 1, P_LEN + W_LEN),
        Vec::<String>::new(),
        "NOT offered again on the daughter's line"
    );
    sd.shutdown();
}

/// R11 — 4d AT A BARE `S` (G1's main fix, the resume's first row): a public
/// carriage `K` of P's citation into a set `S` of the writer's — a
/// `make_link` homed in the published `S`, its `from` P on `E.2` — is live,
/// and its liveness reads TRUE at the member `E.2` and FALSE at the bare
/// `S`, which arranges none of P: a resume reading `discoverable_from {a:
/// K, d: S}` would count a landed carriage as not committed and re-send it,
/// so the design reads at `E.k`, the member its shot minted, whatever the
/// copy's home. Retracted, the carriage reads false at both — a live copy
/// reads committed, a retracted one does not.
#[test]
fn a_carriages_liveness_reads_at_the_member_and_not_at_the_bare_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let c = chain(port, &signed);
    let s = published_edition(port, &signed);
    let k = acked_addr(&op(port, Some(&signed), &citation(&s, &vspec(&c.e2, 1, P_LEN), NONE)));
    assert_eq!(home_of(&k), s, "the carriage is homed in the set");
    assert_eq!(read_link(port, None, &k)["slots"][0], i_slot(&p_run(&c.e).0, P_LEN), "and stands on P's identity");
    assert!(discoverable_from(port, Some(&signed), &k, &c.e2), "live: committed, read at the member");
    assert!(!discoverable_from(port, Some(&signed), &k, &s), "live, yet false at the bare S, which arranges none of P");

    let v = op(port, Some(&signed), &nullify_frame(&s, &k));
    assert_eq!(verdict(&v), "ok", "the carriage is retracted: {v}");
    assert!(!discoverable_from(port, Some(&signed), &k, &c.e2), "retracted: not committed, read at the member");
    assert!(!discoverable_from(port, Some(&signed), &k, &s));
    sd.shutdown();
}
