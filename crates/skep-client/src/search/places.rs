//! THE DOCUMENT INDEX the plane reads (`client.md` §4e.2; A-255; foundations
//! §2.1, §2.3): "addresses, first lines, counts per account — stays the
//! shell's own structure, and the search index is the crate's; both are fed
//! by the one poll — the document index's addresses and counts from the rows
//! themselves and its FIRST LINES from the delivery the consumer already
//! reads for the crate". HELD AS THE SEARCH INDEX IS: a PUBLISHED part fed
//! from the token-free rows and shared on the device, and a part per
//! principal holding what that principal's class adds, so `places` is drawn
//! at the call's class (§4e.5; PATTERNS P39 — a principal's holding is a
//! file of its own). THE PERSISTENCE — the one item the design owed by name
//! ("a file each, or one") — is SETTLED BY P39: ONE FILE PER PART beside its
//! index, `published.places` and `principal-<n>.places`, written by the same
//! rename and deleted with the supplement it belongs to. The form: one JSON
//! line per document in the key file's conventions (`client.md` §3.2) —
//! members in one order, no whitespace outside strings — `doc`, `kind`,
//! `label` (the first line, or `null`) and `member` (the head member the
//! document was last read at, so a restart probes no trunk the file already
//! knows; `null` for a draft read at its own address and a memberless
//! document). The part is DERIVED STATE in the index's sense: a line that
//! does not parse drops the part, and the next poll refills what it reads.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{json, Value};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_search::{Item, Kind, Unit};

use crate::address::parse_address;

/// The most bytes a first line keeps: a label is a line the box shows, not
/// a paragraph.
const LABEL_BOUND: usize = 200;

/// One document's row of the document index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceRecord {
    /// Edition or draft.
    pub kind: Kind,
    /// The member the document was last read at: an edition's head member,
    /// `None` for a draft and for a published document without a member.
    pub member: Option<Address>,
    /// The first line of the document's text, trimmed and bounded; `None`
    /// where it holds no text.
    pub label: Option<String>,
}

/// One PART of the document index: the published part, or one principal's.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Places {
    docs: BTreeMap<Address, PlaceRecord>,
}

/// Why a part's file did not parse — the part is then rebuilt by the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacesError {
    /// The line, 1-based.
    pub line: usize,
}

impl fmt::Display for PlacesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the document index's line {} does not parse", self.line)
    }
}

impl std::error::Error for PlacesError {}

impl Places {
    /// An empty part.
    pub fn new() -> Places {
        Places::default()
    }

    /// The documents held.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// Whether no document is held.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// The row for `doc`, replacing any earlier one.
    pub fn record(&mut self, doc: Address, record: PlaceRecord) {
        self.docs.insert(doc, record);
    }

    /// The row for `doc`, where one stands.
    pub fn get(&self, doc: &Address) -> Option<&PlaceRecord> {
        self.docs.get(doc)
    }

    /// Every row, in address order.
    pub fn docs(&self) -> impl Iterator<Item = (&Address, &PlaceRecord)> {
        self.docs.iter()
    }

    /// THE COUNTS PER ACCOUNT (A-255): how many documents of this part lie
    /// under each account, in address order.
    pub fn counts(&self) -> BTreeMap<Address, usize> {
        let mut counts = BTreeMap::new();
        for doc in self.docs.keys() {
            if let Some(account) = account_of(doc) {
                *counts.entry(account).or_insert(0) += 1;
            }
        }
        counts
    }

    /// THE EXACT MATCHES (§4e.5; foundations §2.3): the documents whose
    /// address is the text — an address parses exact — and those whose label
    /// is the text, trimmed; in address order, each once.
    pub fn matching(&self, text: &str) -> Vec<&Address> {
        let text = text.trim();
        if text.is_empty() {
            return Vec::new();
        }
        let as_address = parse_address(text);
        self.docs
            .iter()
            .filter(|(doc, record)| {
                as_address.as_ref() == Some(*doc) || record.label.as_deref() == Some(text)
            })
            .map(|(doc, _)| doc)
            .collect()
    }

    /// THE FIRST LINE of a unit's text — the text items' bytes through the
    /// first line break, lossily decoded, trimmed, bounded to `LABEL_BOUND`
    /// bytes at a character boundary; `None` for a unit holding no text
    /// before its first break.
    pub fn first_line(unit: &Unit) -> Option<String> {
        let mut bytes: Vec<u8> = Vec::new();
        'items: for item in unit.items() {
            if let Item::Text { bytes: more, .. } = item {
                for &b in more {
                    if b == b'\n' {
                        break 'items;
                    }
                    bytes.push(b);
                    if bytes.len() > LABEL_BOUND * 2 {
                        break 'items;
                    }
                }
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        let mut line = text.trim().to_string();
        if line.len() > LABEL_BOUND {
            let mut cut = LABEL_BOUND;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            line.truncate(cut);
        }
        (!line.is_empty()).then_some(line)
    }

    /// The part's file: one JSON line per document in the key file's
    /// conventions, in address order.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (doc, record) in &self.docs {
            let line = json!({
                "doc": doc.to_string(),
                "kind": match record.kind { Kind::Edition => "edition", Kind::Draft => "draft" },
                "label": record.label,
                "member": record.member.as_ref().map(ToString::to_string),
            });
            out.extend_from_slice(line.to_string().as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// The part read back from its file; a member this build does not know
    /// is ignored (the forward rule), and a line that does not parse refuses
    /// the part.
    pub fn decode(bytes: &[u8]) -> Result<Places, PlacesError> {
        let text = String::from_utf8_lossy(bytes);
        let mut places = Places::new();
        for (i, line) in text.lines().enumerate() {
            let refused = || PlacesError { line: i + 1 };
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(line).map_err(|_| refused())?;
            let doc = v["doc"].as_str().and_then(parse_address).ok_or_else(refused)?;
            let kind = match v["kind"].as_str() {
                Some("edition") => Kind::Edition,
                Some("draft") => Kind::Draft,
                _ => return Err(refused()),
            };
            let member = match &v["member"] {
                Value::Null => None,
                Value::String(s) => Some(parse_address(s).ok_or_else(refused)?),
                _ => return Err(refused()),
            };
            let label = match &v["label"] {
                Value::Null => None,
                Value::String(s) => Some(s.clone()),
                _ => return Err(refused()),
            };
            places.record(doc, PlaceRecord { kind, member, label });
        }
        Ok(places)
    }
}

/// The BARE DOCUMENT an address lies in or names — `N·0·A·0·D` through the
/// first component after the second separator — for a document, a version
/// member (`D.k`, `D.k.j`) or an element of it; `None` for a node or an
/// account. The address a feed row's `docs` entry names is reduced to this
/// key (`search.md` §2.1: the unit key is the bare document address alone).
pub(crate) fn bare_document(addr: &Address) -> Option<Address> {
    let comps: Vec<Nat> = addr.tumbler().iter().cloned().collect();
    let second_zero = zero_index(&comps, 2)?;
    let end = second_zero + 1;
    if end >= comps.len() {
        return None;
    }
    address_of(&comps[..=end])
}

/// The ACCOUNT an address lies under — `N·0·A`, the components before the
/// second separator; `None` for a node address.
pub(crate) fn account_of(addr: &Address) -> Option<Address> {
    let comps: Vec<Nat> = addr.tumbler().iter().cloned().collect();
    let second_zero = zero_index(&comps, 2)?;
    address_of(&comps[..second_zero])
}

/// The trunk member `D.k` of document `doc`.
pub(crate) fn member_of(doc: &Address, k: u64) -> Option<Address> {
    let mut comps: Vec<Nat> = doc.tumbler().iter().cloned().collect();
    comps.push(Nat::from(k));
    address_of(&comps)
}

/// The node's own prefix — the first component of `addr`, under which every
/// address of the board lies.
pub(crate) fn node_of(addr: &Address) -> Option<Address> {
    let first = addr.tumbler().iter().next()?.clone();
    address_of(&[first])
}

/// A T4-valid address from its components, or none.
fn address_of(comps: &[Nat]) -> Option<Address> {
    validate(Tumbler::new(comps.iter().cloned()).ok()?).ok()
}

/// The index of the `n`-th zero component, `n` 1-based.
fn zero_index(comps: &[Nat], n: usize) -> Option<usize> {
    let zero = Nat::from(0u64);
    comps.iter().enumerate().filter(|(_, c)| **c == zero).map(|(i, _)| i).nth(n - 1)
}
