//! THE UN-ARRANGED ATOM (REG-3.25, REG-3.26): a deposit's atom — the address
//! its link's `from` names — is read where its home arranges it: at the head
//! where it is arranged there, and otherwise recovered BY THE HOME'S CHAIN
//! WALK, one version at a time down the home's chain to the version that
//! arranged it, each version asked for its extent, its image and the value —
//! never by a read of the arranged head; the walk probes the home's members
//! off the board itself, so it needs no feed, and its cost is counted
//! ([`ChainWalkStats`](super::ChainWalkStats)). Where no version holds it,
//! the POSITION READ off the feed the mirror holds (`/op-at` at the link's
//! position) is the last recourse; where that fails too the record is
//! UNDETERMINABLE HERE, suppressed and counted.
//!
//! An `impl Mirror` child of `mirror`: a record's bytes from the cache, the
//! head, the chain walk or the position read, reading the mirror's private
//! state the way a child does. The fold calls one method here,
//! [`Mirror::fetch_atom`]; [`Chains`] is the walk's memory between two
//! pulls, which the fold teaches the members a `publish` or a `version` row
//! names and whose stale part the pull forgets.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use skep_address::{document_of, Address, Nat, Tumbler};
use skep_registry::MAX_REGISTRY_RECORD_BYTES;

use super::{Mirror, MirrorError};
use crate::board::{
    atom_of, content_extent, content_ordinal_in, image_frame, retrieve_frame, runs_of, span_set_frame,
    v_ordinal_in,
};
use crate::parse_address;

/// A document's or a member's V→I image: its content runs, in V-order.
#[derive(Debug, Clone)]
struct Image {
    runs: Vec<(Address, u64)>,
}

impl Image {
    /// The V-ordinal `addr` sits at, where the image holds it.
    fn v_ordinal_of(&self, addr: &Address) -> Option<u64> {
        v_ordinal_in(&self.runs, addr)
    }
}

/// THE CHAIN WALK'S MEMORY between two pulls: the members each home's chain
/// is known to hold, the homes whose members need no probe, and the images
/// read — written by the walk, by the fold through [`Chains::learn`], and in
/// part forgotten by the pull through [`Chains::forget_stale`], and by
/// nothing else.
#[derive(Debug, Default)]
pub(super) struct Chains {
    members: BTreeMap<Address, Vec<Address>>,
    /// Every member kept, beside the home it is kept under — a member once
    /// per home, as `members` lists it — so keeping one more asks a set and
    /// never scans the members a home already holds: a `publish` row costs
    /// the fold the same at its ten-thousandth member as at its first.
    known: BTreeSet<(Address, Address)>,
    probed: BTreeSet<Address>,
    images: BTreeMap<Address, Image>,
}

impl Chains {
    /// A member a `publish` or a `version` row names, kept under its trunk,
    /// and the trunk marked probed: a member the feed names needs no probe
    /// to be known.
    pub(super) fn learn(&mut self, member: &Address) {
        let Some(trunk) = trunk_of(member) else { return };
        self.keep(&trunk, member);
        self.probed.insert(trunk);
    }

    /// `member` kept under `home` — its trunk, or the home a probe was made
    /// under — once, in the order members are met.
    fn keep(&mut self, home: &Address, member: &Address) {
        if self.known.insert((home.clone(), member.clone())) {
            self.members.entry(home.clone()).or_default().push(member.clone());
        }
    }

    /// A pull began: the images are forgotten, since the new rows can
    /// rearrange a head, and the probes, since they can add members; the
    /// members known are kept, a member never unregistered.
    pub(super) fn forget_stale(&mut self) {
        self.images.clear();
        self.probed.clear();
    }

    /// The members of `home`'s chain the walk knows, oldest first.
    pub(super) fn members_of(&self, home: &Address) -> &[Address] {
        self.members.get(home).map(Vec::as_slice).unwrap_or(&[])
    }
}

impl Mirror {
    /// THE ATOM at `addr` in `home`: the cache; the head where it is arranged
    /// there (the append-only guess, then the head's whole image); THE CHAIN
    /// WALK down the home's members (REG-3.25); the position read off the
    /// feed (REG-3.26); else `None`.
    pub(super) fn fetch_atom(&mut self, at: u64, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
        if let Some(text) = self.fetched.atoms.get(addr) {
            return Ok(Some(text.clone()));
        }
        if self.board.is_none() {
            return Ok(None);
        }
        // The head, through its cached image where one is held.
        if let Some(ordinal) = self.chains.images.get(home).and_then(|i| i.v_ordinal_of(addr)) {
            if let Some(text) = self.retrieve(home, ordinal)? {
                return self.keep_atom(addr, text);
            }
        }
        // The append-only guess: a doc 1 written only by deposits arranges
        // its content ordinal n at V-ordinal n.
        if self.chains.members_of(home).is_empty() {
            if let Some(n) = content_ordinal_in(home, addr) {
                if let Some(runs) = self.image(home, n, 1)? {
                    if runs.len() == 1 && runs[0].0 == *addr && runs[0].1 == 1 {
                        if let Some(text) = self.retrieve(home, n)? {
                            return self.keep_atom(addr, text);
                        }
                    }
                }
            }
        }
        // The head's whole image.
        if let Some(image) = self.image_of(home)? {
            if let Some(ordinal) = image.v_ordinal_of(addr) {
                if let Some(text) = self.retrieve(home, ordinal)? {
                    return self.keep_atom(addr, text);
                }
            }
        }
        // THE CHAIN WALK (REG-3.25): every member, newest first.
        let t = Instant::now();
        let reads_before = self.board_ref()?.reads().total();
        self.probe_members(home)?;
        let members = self.chains.members_of(home).to_vec();
        let mut visited = 0;
        let mut found = None;
        for member in members.iter().rev() {
            visited += 1;
            if let Some(image) = self.image_of(member)? {
                if let Some(ordinal) = image.v_ordinal_of(addr) {
                    found = self.retrieve(member, ordinal)?;
                    if found.is_some() {
                        break;
                    }
                }
            }
        }
        if visited > 0 {
            self.stats.chain_walk.versions_visited += visited;
            self.stats.chain_walk.reads += self.board_ref()?.reads().total() - reads_before;
            self.stats.chain_walk.time += t.elapsed();
        }
        if let Some(text) = found {
            self.stats.chain_walk.atoms += 1;
            return self.keep_atom(addr, text);
        }
        // THE POSITION READ (REG-3.26), where the reader holds the feed.
        if let Some(text) = self.position_read(at, home, addr)? {
            self.stats.chain_walk.position_reads += 1;
            return self.keep_atom(addr, text);
        }
        Ok(None)
    }

    /// A record's bytes, kept: held, and its line written to the fetch cache
    /// — where they can be a record at all. Bytes past the largest record
    /// the canonical rule admits (`MAX_REGISTRY_RECORD_BYTES`) are handed to
    /// the parse, which refuses them before it reads one, and never held: a
    /// board sizes neither the cache nor its file past a record.
    fn keep_atom(&mut self, addr: &Address, text: String) -> Result<Option<String>, MirrorError> {
        if text.len() > MAX_REGISTRY_RECORD_BYTES {
            return Ok(Some(text));
        }
        let line = self.fetched.keep_atom(addr.clone(), text.clone());
        self.append_cache(line)?;
        Ok(Some(text))
    }

    /// The members of `home`'s chain, probed off the board where the feed
    /// has not named them: `D.1`, `D.2`, … until one is unregistered.
    fn probe_members(&mut self, home: &Address) -> Result<(), MirrorError> {
        if self.chains.probed.contains(home) {
            return Ok(());
        }
        let mut k = 1u64;
        let mut found = Vec::new();
        while let Some(member) = parse_address(&format!("{home}.{k}")) {
            if self.span_set(&member)?.is_none() {
                break;
            }
            found.push(member);
            k += 1;
        }
        for member in &found {
            self.chains.keep(home, member);
        }
        self.chains.probed.insert(home.clone());
        Ok(())
    }

    /// The whole image of `doc` (a document or a member), cached.
    fn image_of(&mut self, doc: &Address) -> Result<Option<Image>, MirrorError> {
        if let Some(i) = self.chains.images.get(doc) {
            return Ok(Some(i.clone()));
        }
        let Some(extent) = self.span_set(doc)? else { return Ok(None) };
        let runs = if extent == 0 { Some(Vec::new()) } else { self.image(doc, 1, extent)? };
        let Some(runs) = runs else { return Ok(None) };
        let image = Image { runs };
        self.chains.images.insert(doc.clone(), image.clone());
        Ok(Some(image))
    }

    /// `retrieve_doc_v_span_set`: the content extent of `doc`, `None` where
    /// the read is refused (an unregistered member).
    fn span_set(&self, doc: &Address) -> Result<Option<u64>, MirrorError> {
        let v = self.board_ref()?.op(&span_set_frame(doc))?;
        if v["resp"].as_str() != Some("span_set") {
            return Ok(None);
        }
        Ok(Some(content_extent(&v).unwrap_or(0)))
    }

    /// `image`: the runs at V-ordinals `from ..` of `doc`, `None` where
    /// refused or where a run does not read.
    fn image(&self, doc: &Address, from: u64, width: u64) -> Result<Option<Vec<(Address, u64)>>, MirrorError> {
        let v = self.board_ref()?.op(&image_frame(doc, from, width))?;
        if v["resp"].as_str() != Some("runs") {
            return Ok(None);
        }
        Ok(runs_of(&v))
    }

    /// `retrieve_v`: the atom at V-ordinal `ordinal` of `doc`, `None` where
    /// refused or no atom stands there.
    fn retrieve(&self, doc: &Address, ordinal: u64) -> Result<Option<String>, MirrorError> {
        let v = self.board_ref()?.op(&retrieve_frame(doc, ordinal))?;
        Ok(atom_of(&v))
    }

    /// THE POSITION READ (REG-3.26): the home as of the link's position,
    /// through `/op-at` — the extent, the image, the value.
    fn position_read(&self, at: u64, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
        let board = self.board_ref()?;
        let v = board.op_at(at, &span_set_frame(home))?;
        let Some(extent) = content_extent(&v) else { return Ok(None) };
        let v = board.op_at(at, &image_frame(home, 1, extent))?;
        let Some(runs) = runs_of(&v) else { return Ok(None) };
        let Some(ordinal) = v_ordinal_in(&runs, addr) else { return Ok(None) };
        let v = board.op_at(at, &retrieve_frame(home, ordinal))?;
        Ok(atom_of(&v))
    }
}

/// The TRUNK of a document or a version member: the document address cut
/// after the document field's first component (`1.0.1.0.1.2` → `1.0.1.0.1`).
fn trunk_of(doc: &Address) -> Option<Address> {
    let d = document_of(doc)?;
    let comps: Vec<Nat> = d.tumbler().iter().cloned().collect();
    let second_zero = comps.iter().enumerate().filter(|(_, c)| **c == Nat::from(0u32)).map(|(i, _)| i).nth(1)?;
    let trunk = Tumbler::new(comps[..=second_zero + 1].iter().cloned()).ok()?;
    skep_address::validate(trunk).ok()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::http::{Method, Transport, TransportError};
    use crate::mirror::testing::{answer, over};

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// THE WALK'S MEMORY: a member a row names is kept under its trunk — a
    /// daughter under the same trunk, an element's document read to its
    /// trunk — once, and the trunk needs no probe; a pull forgets the probes
    /// and the images and keeps the members. A member a probe found under
    /// the home it was made from is kept under its trunk as well once a row
    /// names it: each home lists its members once, whatever another home
    /// lists. An image reads its V-ordinals the board's one way.
    #[test]
    fn the_walk_keeps_its_members_across_a_pull() {
        assert_eq!(trunk_of(&a("1.0.1.0.1.2")), Some(a("1.0.1.0.1")));
        assert_eq!(trunk_of(&a("1.0.1.0.1.2.1")), Some(a("1.0.1.0.1")), "a daughter's trunk");
        assert_eq!(trunk_of(&a("1.0.1.0.1")), Some(a("1.0.1.0.1")));
        assert_eq!(trunk_of(&a("1.0.1.0.1.0.1.4")), Some(a("1.0.1.0.1")));
        let home = a("1.0.1.0.1");
        let mut chains = Chains::default();
        for member in ["1.0.1.0.1.1", "1.0.1.0.1.2", "1.0.1.0.1.1"] {
            chains.learn(&a(member));
        }
        let image = Image { runs: vec![(a("1.0.1.0.1.0.1.1"), 2), (a("1.0.1.0.1.0.1.7"), 3)] };
        assert_eq!(image.v_ordinal_of(&a("1.0.1.0.1.0.1.8")), Some(4));
        chains.images.insert(home.clone(), image);
        assert_eq!(chains.members_of(&home), [a("1.0.1.0.1.1"), a("1.0.1.0.1.2")], "each member once, oldest first");
        assert!(chains.probed.contains(&home), "a member the feed names needs no probe");
        chains.forget_stale();
        assert_eq!(chains.members_of(&home), [a("1.0.1.0.1.1"), a("1.0.1.0.1.2")], "a pull keeps the members");
        assert!(chains.probed.is_empty() && chains.images.is_empty(), "and forgets the probes and the images");
        assert!(chains.members_of(&a("1.0.2.0.1")).is_empty());
        let (version, daughter) = (a("1.0.1.0.1.1"), a("1.0.1.0.1.1.1"));
        chains.keep(&version, &daughter);
        chains.learn(&daughter);
        assert_eq!(chains.members_of(&version), std::slice::from_ref(&daughter), "under the home its probe was made from");
        let trunk_members = [a("1.0.1.0.1.1"), a("1.0.1.0.1.2"), daughter];
        assert_eq!(chains.members_of(&home), trunk_members, "and under its trunk once a row names it");
    }

    /// A BOARD WHOSE HOME `1.0.2.0.1` ARRANGES `…0.1.2` NOWHERE AT ITS HEAD: the
    /// head arranges `…0.1.9` alone and the home's chain has no member; as of
    /// position 7 the home arranged `…0.1.9` then `…0.1.2` where `places`, and
    /// is refused otherwise. Any other read — a value read at the head, or one
    /// at another V-ordinal or another position — is no read this board
    /// answers.
    struct Unarranged {
        places: bool,
    }

    impl Transport for Unarranged {
        fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
            let request: Value = serde_json::from_slice(body).expect("a JSON body");
            let (frame, at) = if path == "/op-at" { (&request["frame"], request["at"].as_u64()) } else { (&request, None) };
            let doc = frame["doc"].as_str().or(frame["d"].as_str()).or(frame["specs"][0]["doc"].as_str());
            let runs = |starts: &[&str]| {
                json!({ "resp": "runs", "runs": starts.iter().map(|s| json!({ "i_start": s, "width": "1" })).collect::<Vec<_>>() })
            };
            let set = |width: &str| json!({ "resp": "span_set", "set": [{ "start": "1.1", "width": width }] });
            let refused = json!({ "resp": "rejected", "op": frame["op"], "code": "doc_not_registered" });
            let at_ordinal_2 = frame["specs"][0]["span"]["start"] == "1.2";
            assert_eq!(method, Method::Post, "{path}");
            match (frame["op"].as_str(), doc, at) {
                (Some("image"), Some("1.0.2.0.1"), None) => answer(runs(&["1.0.2.0.1.0.1.9"])),
                (Some("retrieve_doc_v_span_set"), Some("1.0.2.0.1"), None) => answer(set("0.1")),
                (Some("retrieve_doc_v_span_set"), Some(_), None) => answer(refused),
                (Some("retrieve_doc_v_span_set"), Some("1.0.2.0.1"), Some(7)) if self.places => answer(set("0.2")),
                (Some("retrieve_doc_v_span_set"), Some("1.0.2.0.1"), Some(7)) => answer(refused),
                (Some("image"), Some("1.0.2.0.1"), Some(7)) => answer(runs(&["1.0.2.0.1.0.1.9", "1.0.2.0.1.0.1.2"])),
                (Some("retrieve_v"), Some("1.0.2.0.1"), Some(7)) if at_ordinal_2 => {
                    answer(json!({ "resp": "delivery", "items": [{ "atom": "the bytes as of 7" }] }))
                }
                _ => panic!("a read this board does not answer: {path} {request}"),
            }
        }
    }

    /// THE POSITION READ (REG-3.26), the last recourse: an atom its home's head
    /// does not arrange and no version of the home holds is read as of its
    /// link's position through `/op-at` — the extent, the image, the value at
    /// the V-ordinal that image places it — kept, and counted; where the home
    /// as of that position arranges nothing either, there are no bytes.
    #[test]
    fn an_atom_no_version_holds_is_read_as_of_its_links_position() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (home, atom) = (a("1.0.2.0.1"), a("1.0.2.0.1.0.1.2"));
        let mut mirror = over(Unarranged { places: true }, dir.path());
        assert_eq!(mirror.fetch_atom(7, &home, &atom), Ok(Some("the bytes as of 7".to_string())));
        assert_eq!(mirror.stats.chain_walk.position_reads, 1);
        assert_eq!(mirror.fetched.atoms.get(&atom).map(String::as_str), Some("the bytes as of 7"), "kept");
        let mut mirror = over(Unarranged { places: false }, dir.path());
        assert_eq!(mirror.fetch_atom(7, &home, &atom), Ok(None), "the home as of 7 arranges nothing");
        assert_eq!(mirror.stats.chain_walk.position_reads, 0);
    }

    /// A BOARD WHOSE HOME `1.0.2.0.1` ARRANGES ITS ATOM `…0.1.1` AT THE HEAD,
    /// the bytes there `len` long.
    struct Lengthy {
        len: usize,
    }

    impl Transport for Lengthy {
        fn exchange(&self, _: Method, _: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
            let frame: Value = serde_json::from_slice(body).expect("a frame");
            match frame["op"].as_str() {
                Some("image") => answer(json!({ "resp": "runs", "runs": [{ "i_start": "1.0.2.0.1.0.1.1", "width": "1" }] })),
                Some("retrieve_v") => answer(json!({ "resp": "delivery", "items": [{ "atom": "x".repeat(self.len) }] })),
                _ => panic!("a read this board does not answer: {frame}"),
            }
        }
    }

    /// BYTES PAST ANY RECORD ARE NEVER HELD: an atom longer than the largest
    /// record the canonical rule admits is handed to the parse, which refuses
    /// it, and kept neither in the cache nor in its file; a record's own bytes,
    /// at that length, are kept.
    #[test]
    fn bytes_past_any_record_are_handed_to_the_parse_and_never_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (home, atom) = (a("1.0.2.0.1"), a("1.0.2.0.1.0.1.1"));
        let mut mirror = over(Lengthy { len: MAX_REGISTRY_RECORD_BYTES + 1 }, dir.path());
        let bytes = mirror.fetch_atom(5, &home, &atom).expect("read").expect("the bytes");
        assert_eq!(bytes.len(), MAX_REGISTRY_RECORD_BYTES + 1, "handed to the parse");
        assert!(mirror.fetched.atoms.is_empty() && mirror.pending_cache.is_empty(), "never held");
        let mut mirror = over(Lengthy { len: MAX_REGISTRY_RECORD_BYTES }, dir.path());
        mirror.fetch_atom(5, &home, &atom).expect("read").expect("the bytes");
        assert_eq!((mirror.fetched.atoms.len(), mirror.pending_cache.len()), (1, 1), "a record's bytes, held");
    }
}
