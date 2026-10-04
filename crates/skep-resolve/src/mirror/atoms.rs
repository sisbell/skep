//! THE UN-ARRANGED ATOM (REG-3.25, REG-3.26): a deposit's atom is read at the
//! position its link's `from` names — at the head where it is arranged
//! there, and otherwise recovered BY THE HOME'S CHAIN WALK, one version at a
//! time down the home's chain to the version that arranged it, each version
//! asked for its extent, its image and the value — never by a read of the
//! arranged head; the walk probes the home's members off the board itself,
//! so it needs no feed, and its cost is counted
//! ([`WalkStats`](super::WalkStats)). Where no version holds it, the
//! POSITION READ off the feed the mirror holds (`/op-at` at the link's
//! position) is the last recourse; where that fails too the record is
//! UNDETERMINABLE HERE, suppressed and counted.
//!
//! An `impl Mirror` child of `mirror`: a record's bytes from the cache, the
//! head, the chain walk or the position read, reading the mirror's private
//! state the way a child does. The fold calls one method here,
//! [`Mirror::fetch_atom`]; [`Image`] is the value of the mirror's image
//! cache.

use std::time::Instant;

use serde_json::{json, Value};
use skep_address::{document_of, Address, Nat};

use super::{Mirror, MirrorError};
use crate::board::{content_extent, position_in, retrieve_frame};
use crate::parse_address;

/// A document's or a member's V→I image: its content runs, in V-order.
#[derive(Debug, Clone)]
pub(super) struct Image {
    runs: Vec<(Address, u64)>,
}

impl Image {
    /// The V-ordinal `addr` sits at, where the image holds it.
    fn position_of(&self, addr: &Address) -> Option<u64> {
        position_in(&self.runs, addr)
    }
}

impl Mirror {
    /// THE ATOM at `addr` in `home`: the cache; the head where it is arranged
    /// there (the append-only guess, then the head's whole image); THE CHAIN
    /// WALK down the home's members (REG-3.25); the position read off the
    /// feed (REG-3.26); else `None`.
    pub(super) fn fetch_atom(&mut self, at: u64, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
        if let Some(t) = self.fetched.atoms.get(addr) {
            return Ok(Some(t.clone()));
        }
        if self.board.is_none() {
            return Ok(None);
        }
        // The head, through its cached image where one is held.
        if let Some(pos) = self.images.get(home).and_then(|i| i.position_of(addr)) {
            if let Some(text) = self.retrieve(home, pos)? {
                return self.keep_atom(addr, text);
            }
        }
        // The append-only guess: a doc 1 written only by deposits arranges
        // its content ordinal n at V-ordinal n.
        let has_members = self.members.get(home).is_some_and(|m| !m.is_empty());
        if !has_members {
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
            if let Some(pos) = image.position_of(addr) {
                if let Some(text) = self.retrieve(home, pos)? {
                    return self.keep_atom(addr, text);
                }
            }
        }
        // THE CHAIN WALK (REG-3.25): every member, newest first.
        let t = Instant::now();
        let reads_before = self.board_ref()?.reads().total();
        self.probe_members(home)?;
        let members = self.members.get(home).cloned().unwrap_or_default();
        let mut visited = 0;
        let mut found = None;
        for member in members.iter().rev() {
            visited += 1;
            if let Some(image) = self.image_of(member)? {
                if let Some(pos) = image.position_of(addr) {
                    found = self.retrieve(member, pos)?;
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

    /// A record's bytes, kept: held, and its line written to the fetch cache.
    fn keep_atom(&mut self, addr: &Address, text: String) -> Result<Option<String>, MirrorError> {
        let line = self.fetched.keep_atom(addr.clone(), text.clone());
        self.append_cache(line)?;
        Ok(Some(text))
    }

    /// The members of `home`'s chain, probed off the board where the feed
    /// has not named them: `D.1`, `D.2`, … until one is unregistered.
    fn probe_members(&mut self, home: &Address) -> Result<(), MirrorError> {
        if self.members_probed.get(home).copied().unwrap_or(false) {
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
        let list = self.members.entry(home.clone()).or_default();
        for m in found {
            if !list.contains(&m) {
                list.push(m);
            }
        }
        self.members_probed.insert(home.clone(), true);
        Ok(())
    }

    /// The whole image of `doc` (a document or a member), cached.
    fn image_of(&mut self, doc: &Address) -> Result<Option<Image>, MirrorError> {
        if let Some(i) = self.images.get(doc) {
            return Ok(Some(i.clone()));
        }
        let Some(extent) = self.span_set(doc)? else { return Ok(None) };
        let runs = if extent == 0 { Some(Vec::new()) } else { self.image(doc, 1, extent)? };
        let Some(runs) = runs else { return Ok(None) };
        let image = Image { runs };
        self.images.insert(doc.clone(), image.clone());
        Ok(Some(image))
    }

    /// `retrieve_doc_v_span_set`: the content extent of `doc`, `None` where
    /// the read is refused (an unregistered member).
    fn span_set(&self, doc: &Address) -> Result<Option<u64>, MirrorError> {
        let v = self.board_ref()?.op(&json!({ "op": "retrieve_doc_v_span_set", "doc": doc.to_string() }))?;
        if v["resp"].as_str() != Some("span_set") {
            return Ok(None);
        }
        Ok(Some(content_extent(&v).unwrap_or(0)))
    }

    /// `image`: the runs at content ordinals `from ..` of `doc`, `None`
    /// where refused.
    fn image(&self, doc: &Address, from: u64, width: u64) -> Result<Option<Vec<(Address, u64)>>, MirrorError> {
        let v = self.board_ref()?.op(&json!({ "op": "image", "d": doc.to_string(), "region": [{ "start": format!("1.{from}"), "width": format!("0.{width}") }] }))?;
        if v["resp"].as_str() != Some("runs") {
            return Ok(None);
        }
        Ok(runs_of(&v))
    }

    /// `retrieve_v`: the atom at content ordinal `pos` of `doc`, `None`
    /// where refused or no atom stands there.
    fn retrieve(&self, doc: &Address, pos: u64) -> Result<Option<String>, MirrorError> {
        let v = self.board_ref()?.op(&retrieve_frame(&doc.to_string(), pos))?;
        Ok(atom_of(&v))
    }

    /// THE POSITION READ (REG-3.26): the home as of the link's position,
    /// through `/op-at` — the extent, the image, the value.
    fn position_read(&self, at: u64, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
        let board = self.board_ref()?;
        let v = board.op_at(at, &json!({ "op": "retrieve_doc_v_span_set", "doc": home.to_string() }))?;
        let Some(extent) = content_extent(&v) else { return Ok(None) };
        let v = board.op_at(at, &json!({ "op": "image", "d": home.to_string(), "region": [{ "start": "1.1", "width": format!("0.{extent}") }] }))?;
        let Some(runs) = runs_of(&v) else { return Ok(None) };
        let Some(pos) = (Image { runs }).position_of(addr) else { return Ok(None) };
        let v = board.op_at(at, &retrieve_frame(&home.to_string(), pos))?;
        Ok(atom_of(&v))
    }
}

/// The one atom a one-position delivery carries, where it carries one.
fn atom_of(v: &Value) -> Option<String> {
    if v["resp"].as_str() != Some("delivery") {
        return None;
    }
    let items = v["items"].as_array()?;
    if items.len() != 1 {
        return None;
    }
    items[0]["atom"].as_str().map(str::to_string)
}

/// A `runs` answer as `(i_start, width)` pairs.
fn runs_of(v: &Value) -> Option<Vec<(Address, u64)>> {
    v["runs"].as_array()?.iter().map(|r| {
        let start = parse_address(r["i_start"].as_str()?)?;
        let width = r["width"].as_str()?.parse::<u64>().ok()?;
        Some((start, width))
    }).collect()
}

/// Where `addr` is a content element of `home` itself — `home.0.1.n` — its
/// ordinal `n`.
fn content_ordinal_in(home: &Address, addr: &Address) -> Option<u64> {
    if document_of(addr)? != *home {
        return None;
    }
    let element = addr.element_field()?;
    if element.len() != 2 || element[0] != Nat::from(1u32) {
        return None;
    }
    u64::try_from(&element[1]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// The address arithmetic the append-only guess rests on: a content
    /// element's ordinal in its own document — never a link element's, nor a
    /// member's mint. An image reads its positions the board's one way.
    #[test]
    fn a_content_elements_ordinal_is_read_in_its_own_document() {
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.1.4")), Some(4));
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.2.4")), None, "a link element");
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.1.0.1.4")), None, "a member's mint");
        let image = Image { runs: vec![(a("1.0.1.0.1.0.1.1"), 2), (a("1.0.1.0.1.0.1.7"), 3)] };
        assert_eq!(image.position_of(&a("1.0.1.0.1.0.1.8")), Some(4));
    }
}
