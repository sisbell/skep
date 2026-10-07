//! THE FETCH CACHE'S FORMAT — `fetched.jsonl`, what the fold read off the
//! board — and its one writer and one reader. Each kind of line is spelled
//! by one `keep_*` method of [`Fetched`], which holds the value and answers
//! the line, and read back by [`Fetched::recall`]:
//!
//! * `{"link":{…}}` — a stored link's type and slots: its slots for a link
//!   of a type the fold reads, none for any other;
//! * `{"atom":{"address","text"}}` — a record's bytes;
//! * `{"keys":{"account","epoch","at","enrolled":[…]}}` — a credential table
//!   as of a position;
//! * `{"retracted":{"at","link"}}` — a deposit the fold found off the
//!   board's active view at a `nullify` row;
//! * `{"board":{"position","chain"}}` — the board term;
//! * `{"claim":{"at","claimant"}}` — the claim.
//!
//! A `keep_*` answers a line only for a value it does not hold already — a
//! credential table counting as held where the same keys stand under its
//! account and epoch — so a value read twice, or read again by a resume's
//! fold, is written once. A line is read back whole or not at all: one of no
//! kind this format writes, or one a member of which does not read, holds
//! nothing, and the fold fetches afresh what it would have held. The file is
//! loaded a line at a time ([`Mirror::load_cache`]), so a line that is no
//! JSON — a write a crash cut short — is passed over and refuses nothing.
//!
//! A child of `mirror`, reading the mirror's private types the way a child
//! does.

use std::fs::File;
use std::io::{self, BufRead, BufReader};

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{BoardTerm, Enrolled, PublicKey};

use super::{Epoch, Fetched, KeysAsOf, Mirror, MirrorError, StoredLink, FETCH_CACHE};
use crate::board::parse_chain;
use crate::parse_address;

impl Fetched {
    /// One line of `fetched.jsonl` taken back into memory; a line of no kind
    /// this format writes, or one that does not read whole, holds nothing —
    /// the fold then fetches what it would have held afresh.
    fn recall(&mut self, line: &Value) {
        if let Some(l) = line.get("link") {
            if let Some(link) = stored_link_of(l) {
                self.links.insert(link.address.clone(), link);
            }
        } else if let Some(a) = line.get("atom") {
            if let (Some(addr), Some(text)) = (a["address"].as_str().and_then(parse_address), a["text"].as_str()) {
                self.atoms.insert(addr, text.to_string());
            }
        } else if let Some(k) = line.get("keys") {
            if let Some(keys) = keys_of(k) {
                self.keys.insert((keys.account.clone(), keys.epoch), keys);
            }
        } else if let Some(r) = line.get("retracted") {
            if let (Some(at), Some(link)) = (r["at"].as_u64(), r["link"].as_str().and_then(parse_address)) {
                self.retracted.entry(at).or_default().push(link);
            }
        } else if let Some(b) = line.get("board") {
            if let (Some(p), Some(c)) = (b["position"].as_u64(), b["chain"].as_str().and_then(parse_chain)) {
                self.board_term = Some(BoardTerm { log_position: p, chain: c });
            }
        } else if let Some(c) = line.get("claim") {
            if let (Some(at), Some(who)) = (c["at"].as_u64(), c["claimant"].as_str().and_then(parse_address)) {
                self.claim = Some((at, who));
            }
        }
    }

    /// A stored link held; its `{"link":{…}}` line, where it is new.
    pub(super) fn keep_link(&mut self, link: StoredLink) -> Option<Value> {
        if self.links.get(&link.address) == Some(&link) {
            return None;
        }
        let line = json!({ "link": {
            "at": link.at,
            "address": link.address.to_string(),
            "home": link.home.to_string(),
            "ty": link.ty.as_ref().map(ToString::to_string),
            "from": link.from.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "to": link.to.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }});
        self.links.insert(link.address.clone(), link);
        Some(line)
    }

    /// A record's bytes held; its `{"atom":{…}}` line, where they are new.
    pub(super) fn keep_atom(&mut self, address: Address, text: String) -> Option<Value> {
        if self.atoms.get(&address) == Some(&text) {
            return None;
        }
        let line = json!({ "atom": { "address": address.to_string(), "text": text } });
        self.atoms.insert(address, text);
        Some(line)
    }

    /// A credential table held under its epoch; its `{"keys":{…}}` line, each
    /// enrolled key spelled as [`enrolled_line_of`] reads it back, where the
    /// account's table at that epoch is not these keys already.
    pub(super) fn keep_keys(&mut self, keys: KeysAsOf) -> Option<Value> {
        let account_epoch = (keys.account.clone(), keys.epoch);
        if self.keys.get(&account_epoch).is_some_and(|held| held.enrolled == keys.enrolled) {
            return None;
        }
        let line = json!({ "keys": {
            "account": keys.account.to_string(),
            "epoch": keys.epoch.0,
            "at": keys.at,
            "enrolled": keys.enrolled.iter().map(|e| json!({ "alg": e.key.alg(), "key": e.key.to_hex(), "anchor": e.anchor })).collect::<Vec<_>>(),
        }});
        self.keys.insert(account_epoch, keys);
        Some(line)
    }

    /// A retraction held; its `{"retracted":{…}}` line, where it is new.
    pub(super) fn keep_retracted(&mut self, at: u64, link: Address) -> Option<Value> {
        if self.retracted.get(&at).is_some_and(|held| held.contains(&link)) {
            return None;
        }
        let line = json!({ "retracted": { "at": at, "link": link.to_string() } });
        self.retracted.entry(at).or_default().push(link);
        Some(line)
    }

    /// The board term held; its `{"board":{…}}` line, the chain as the board
    /// spelled it, where the term is new.
    pub(super) fn keep_board(&mut self, term: BoardTerm, chain: &str) -> Option<Value> {
        if self.board_term == Some(term) {
            return None;
        }
        self.board_term = Some(term);
        Some(json!({ "board": { "position": term.log_position, "chain": chain } }))
    }

    /// The claim held; its `{"claim":{…}}` line, where it is new.
    pub(super) fn keep_claim(&mut self, at: u64, claimant: Address) -> Option<Value> {
        if self.claim.as_ref().is_some_and(|(held_at, held)| *held_at == at && *held == claimant) {
            return None;
        }
        let line = json!({ "claim": { "at": at, "claimant": claimant.to_string() } });
        self.claim = Some((at, claimant));
        Some(line)
    }
}

impl Mirror {
    /// The fetch cache read into memory, a line at a time through
    /// [`Fetched::recall`]: a line that does not read — a write a crash cut
    /// short among them, or bytes that are no UTF-8 — holds nothing, and the
    /// fold fetches afresh what it would have held. Refused only where the
    /// file cannot be read at all; none where it is absent.
    pub(super) fn load_cache(&mut self) -> Result<(), MirrorError> {
        let path = self.dir.join(FETCH_CACHE);
        let failed = |e: io::Error| MirrorError::Copy(format!("{}: {e}", path.display()));
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(failed(e)),
        };
        for line in BufReader::new(file).split(b'\n') {
            if let Ok(line) = serde_json::from_slice::<Value>(&line.map_err(failed)?) {
                self.fetched.recall(&line);
            }
        }
        Ok(())
    }
}

/// A stored link line read back — whole, or not at all, as [`keys_of`] reads
/// a table: a member that does not read refuses the line, so the cache never
/// holds a link of fewer addresses than the one it kept — an emptied `to`
/// would read a binding as a retirement, and frame its record under another
/// target.
fn stored_link_of(l: &Value) -> Option<StoredLink> {
    let addrs = |member: &str| -> Option<Vec<Address>> {
        l[member].as_array()?.iter().map(|a| a.as_str().and_then(parse_address)).collect()
    };
    let ty = match l.get("ty")? {
        Value::Null => None,
        ty => Some(parse_address(ty.as_str()?)?),
    };
    Some(StoredLink {
        at: l["at"].as_u64()?,
        address: parse_address(l["address"].as_str()?)?,
        home: parse_address(l["home"].as_str()?)?,
        ty,
        from: addrs("from")?,
        to: addrs("to")?,
    })
}

/// A keys line read back — whole, or not at all: an entry that does not read
/// refuses the line, so the cache never holds a smaller table than the one
/// it kept.
fn keys_of(k: &Value) -> Option<KeysAsOf> {
    Some(KeysAsOf {
        account: parse_address(k["account"].as_str()?)?,
        epoch: Epoch(k["epoch"].as_u64()?),
        at: k["at"].as_u64()?,
        enrolled: k["enrolled"].as_array()?.iter().map(enrolled_line_of).collect::<Option<_>>()?,
    })
}

/// One enrolled key as a keys line spells it — `alg`, `key` (hex), `anchor`
/// — the cache's own spelling, as [`Fetched::keep_keys`] writes it.
fn enrolled_line_of(e: &Value) -> Option<Enrolled> {
    let key = PublicKey::parse(e["alg"].as_str()?, e["key"].as_str()?).ok()?;
    Some(Enrolled { key, anchor: e["anchor"].as_bool()? })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::testing::key;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
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
}
