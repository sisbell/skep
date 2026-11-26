//! `text.edit`: several text edits of a draft in one call (skep #1079).
//!
//! A caller changes a draft as a list of exact edits — "replace this text
//! with that, and that with this" — and hands the list over in one call,
//! `text.edit(session, {doc, edits: [{old, new}, …]})`, the `text` family's
//! second, which lands all of them or none, in one commit (skep #1082). The
//! module makes each pair as `text.replace` makes its one, out of the
//! parent's own pieces — its read, its text, its one write and what settles
//! a lost answer, under the session the call stands under — and adds three
//! things to them.
//!
//! **Checked first** ([`plan`]). The draft's text is read once. Each pair's
//! `old` is then found in the text as the pairs before it leave it — the
//! read's text, changed in memory alone (`Text::splice`) — where it must
//! stand exactly once, as `text.replace` finds one; a pair that does not is
//! the call's refusal, naming the pair, with nothing written (SP-8). The
//! plan costs one find over the text and one splice of it for each pair.
//!
//! **Minimal changes.** A pair is made as the changes between its `old` and
//! its `new` (`skep_client::text::minimal_changes`), never as one stretch:
//! an `old` that spans two changes leaves the text between them standing at
//! the identity it had, and a link on it still follows.
//!
//! **One frame** ([`net`]). The call writes once: the board's `edit`
//! (wire.md §Arrangement), every change of the call in one commit, typed
//! against the read's position, so the call lands whole or not at all and
//! nothing is ever taken back. No image of the draft is read for it. The
//! frame's changes are the call's NET changes, in the coordinates of the
//! draft as read, ascending and apart, as the board takes them: each is a
//! run of positions the draft held as read that the text the call leaves
//! keeps none of, and the bytes that text holds in their place
//! (`rows::Pieces`, which the plan splices in step with the text). So a
//! pair whose `old` covers bytes an earlier pair of the call inserted mints
//! only what stands in the end, and removes nothing the call itself minted;
//! pairs that leave the text as it was read write nothing, and the call
//! answers `unchanged`.
//!
//! **The addresses.** The board mints a frame's values in the frame's
//! order, which is the order of the draft's positions, not the pairs': the
//! acknowledgment names the first, and every byte the frame mints stands at
//! that address plus the bytes the frame mints before it. Each change of
//! the plan is answered with the address of its own new bytes where they
//! stand in the text the call leaves whole and side by side — where no
//! later pair of the call removed one of them or wrote between two of them
//! ([`Standing`]) — and with none where a later pair did.
//!
//! **The answer.** One JSON object keyed by `outcome`, as `text.replace`'s
//! is: `edited`, each pair's changes in the pairs' order; `unchanged`;
//! `refused`, nothing written; and `answer_lost`, an error (`shapes`'
//! `TextEdited`, `TextEditUnchanged`, `TextRefused`, `TextAnswerLost`). A
//! change is named by its ordinal in the draft as the changes planned
//! before it leave it, the bytes it removed and inserted, the I-address its
//! new bytes were minted at and the call's commit, so a caller finds what
//! stands by identity whatever was written after it. An answer lost and
//! settled from the change feed is `edited` at its row's position, no
//! address named (the parent module's *A lost answer*).
//!
//! **The rows** (skep #1080; the sibling module `rows`). `edited` carries the
//! lines the call changed, numbered, as `lines`, and `masked` beside them
//! where a withheld run stands on or before a line they show. They are drawn
//! from the plan's own text — the one read with every pair spliced in, which
//! is the draft exactly as the call's commit left it — and from where each
//! of its positions came from; no read is made for them.

use std::ops::Range;

use serde_json::{json, Value};
use skep_client::address::is_address_text;
use skep_client::board::frames;
use skep_client::text::minimal_changes;

use super::rows::{rows, Pieces, Rows};
use super::{answer_lost, read_draft, refused, refused_write, send_edit, Answer, Calls, Edit, Found, Landing, Read, Text, MAX_NEW_BYTES};
use crate::attest::MAX_WIRE_LIST;
use crate::refusal::Refusal;

/// One pair of the call's: the text to replace, and its replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Pair<'a> {
    /// The text to replace, not empty.
    pub(super) old: &'a str,
    /// The text to stand in its place, empty where `old` is only removed.
    pub(super) new: &'a str,
}

/// What the call is asked: the draft, and its pairs in their order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Asked<'a> {
    /// The draft, an address in its one spelling.
    doc: &'a str,
    /// The pairs, one or more and no more than one wire list holds.
    pairs: Vec<Pair<'a>>,
}

impl<'a> Asked<'a> {
    /// Reads `text.edit`'s members off `args`, each in its form.
    ///
    /// # Errors
    ///
    /// `malformed_args` naming the first member not of its form, in this
    /// order: `doc` where it is no address in its one spelling; `edits`
    /// where it is no list, holds no pair, or holds more than one wire list
    /// carries ([`MAX_WIRE_LIST`]); then, for the first pair `k` not of its
    /// form, `edits[k]` where it is no object, `edits[k].old` where that is
    /// no string or is empty, `edits[k].new` where that is no string.
    pub(super) fn read(args: &'a Value) -> Result<Asked<'a>, Refusal> {
        let doc = args["doc"].as_str().filter(|doc| is_address_text(doc)).ok_or_else(|| Refusal::malformed("doc"))?;
        let edits = args["edits"].as_array().filter(|edits| !edits.is_empty() && edits.len() <= MAX_WIRE_LIST).ok_or_else(|| Refusal::malformed("edits"))?;
        let mut pairs = Vec::with_capacity(edits.len());
        for (k, pair) in edits.iter().enumerate() {
            if !pair.is_object() {
                return Err(Refusal::malformed(format!("edits[{k}]")));
            }
            let old = pair["old"].as_str().filter(|old| !old.is_empty()).ok_or_else(|| Refusal::malformed(format!("edits[{k}].old")))?;
            let new = pair["new"].as_str().ok_or_else(|| Refusal::malformed(format!("edits[{k}].new")))?;
            pairs.push(Pair { old, new });
        }
        Ok(Asked { doc, pairs })
    }

    /// Returns the draft the call edits.
    pub(super) fn doc(&self) -> &'a str {
        self.doc
    }
}

/// One change of the plan.
///
/// It is the pair it is of, its place among the pair's changes, and the
/// edit it makes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Planned<'a> {
    /// The index of its pair in the call's `edits`.
    pair: usize,
    /// Its index among its pair's changes, ascending in the text.
    change: usize,
    /// The edit, its ordinal in the draft as the changes planned before it
    /// leave it.
    edit: Edit<'a>,
}

/// The new bytes of one planned change, where they stand in the text as
/// planned so far.
///
/// One is kept for a change only while its bytes stand whole and side by
/// side: a later pair that removes one of them, or writes between two of
/// them, drops it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Standing {
    /// The index of the change among the plan's.
    planned: usize,
    /// The position of its first new byte.
    at: u64,
    /// How many new bytes it holds, a position each.
    len: u64,
}

/// The call's changes as planned, and the text they leave told by origin.
#[derive(Debug)]
pub(super) struct Plan<'a> {
    /// The changes, pair by pair in the call's order.
    changes: Vec<Planned<'a>>,
    /// The changes whose new bytes stand whole in the text the call leaves,
    /// each with the position of its first new byte there.
    standing: Vec<Standing>,
    /// Where each position of the text the changes leave came from, which
    /// the frame's changes are cut from and the rows of an `edited` answer
    /// are drawn by.
    pub(super) pieces: Pieces<'a>,
}

/// Plans the call: every pair checked, and made its changes.
///
/// Each pair's `old` is found in `text` as the pairs before it leave it,
/// its minimal changes placed from where it stands, and `text` made to read
/// as the pair leaves it, its pieces spliced in step (`rows::Pieces`) and
/// the new bytes of the changes before it moved, or dropped where the pair
/// removes one or writes between two ([`Standing`]). `as_of` is the
/// position `text` was read at. Nothing is written.
///
/// # Errors
///
/// The call's own answer for the first pair that fails, naming it (`pair`):
/// `not_found`, `not_unique` with the count and `crosses_atom` with the
/// value that is no text, each as `text.replace` answers it, the ordinal a
/// place in the text as the pairs before leave it.
pub(super) fn plan<'a>(doc: &str, text: &mut Text, as_of: u64, pairs: &[Pair<'a>]) -> Result<Plan<'a>, Answer> {
    let (mut changes, mut standing, mut pieces) = (Vec::new(), Vec::<Standing>::new(), Pieces::of(text.positions()));
    for (k, pair) in pairs.iter().enumerate() {
        let found = match text.find(pair.old.as_bytes()) {
            Found::Once(ordinal) => ordinal,
            Found::Nowhere => return Err(refused(doc, "not_found", json!({"count": 0, "as_of": as_of, "pair": k}))),
            Found::Many(count) => return Err(refused(doc, "not_unique", json!({"count": count, "as_of": as_of, "pair": k}))),
            Found::Across { ordinal, kind } => return Err(refused(doc, "crosses_atom", json!({"ordinal": ordinal.to_string(), "kind": kind, "as_of": as_of, "pair": k}))),
        };
        let minimal = minimal_changes(pair.old, pair.new);
        // The new bytes of the changes before this pair: each run moved by
        // the pair's changes before it, and dropped where one of them
        // removes a byte of it or inserts between two.
        standing.retain_mut(|run| {
            let (first, past) = (run.at, run.at + run.len);
            let (mut added, mut removed) = (0u64, 0u64);
            for change in &minimal {
                let (from, to) = (found + change.old.start as u64, found + change.old.end as u64);
                let cut = if to > from { from < past && to > first } else { first < from && from < past };
                if cut {
                    return false;
                }
                if to <= first {
                    added += change.new.len() as u64;
                    removed += change.old.len() as u64;
                }
            }
            // The changes counted lie before the run, so they remove no
            // more positions than stand before it.
            run.at = first - removed + added;
            true
        });
        for (j, change) in minimal.iter().enumerate() {
            // The changes before this one in the pair are made by its turn:
            // up to its first byte the pair's stretch reads as its new text.
            let ordinal = found.saturating_add(change.new.start as u64);
            if !change.new.is_empty() {
                standing.push(Standing { planned: changes.len(), at: ordinal, len: change.new.len() as u64 });
            }
            changes.push(Planned { pair: k, change: j, edit: Edit { ordinal, removed: change.old.len() as u64, inserted: &pair.new[change.new.clone()] } });
        }
        pieces.splice(found, pair.old, &minimal);
        text.splice(found, pair.old.len(), pair.new.as_bytes());
    }
    Ok(Plan { changes, standing, pieces })
}

/// One change of the call's frame.
///
/// It is a run of the draft's positions as read that the text the call
/// leaves keeps none of, and the bytes that text holds in their place.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Net {
    /// The first position removed as the draft was read, or the one the new
    /// bytes are placed before where none is.
    at: u64,
    /// How many positions of the draft as read are removed.
    width: u64,
    /// The positions of the new bytes in the text the call leaves.
    new: Range<u64>,
}

impl Net {
    /// Returns how many bytes the change mints.
    fn minted(&self) -> u64 {
        self.new.end - self.new.start
    }

    /// Returns the change as the frame spells it, its new bytes read off
    /// `text`, the text the call leaves.
    ///
    /// The bytes are text the pairs spelled, sent as text; bytes that are no
    /// UTF-8 would go as hex, a value a byte all the same.
    fn frame(&self, text: &Text) -> Value {
        let bytes = text.bytes_at(self.new.start, self.new.end);
        match std::str::from_utf8(bytes) {
            Ok(new) => frames::minted(self.at, self.width, new),
            Err(_) => json!({"at": frames::place(self.at), "width": self.width.to_string(), "values": [{"hex": bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()}]}),
        }
    }
}

/// Returns the call's net changes: the frame's changes, in its order.
///
/// They are `pieces`' stretches of changes, each a change of the draft as
/// read: ascending in its positions and apart, a kept position standing
/// between any two.
fn net(pieces: &Pieces<'_>) -> Vec<Net> {
    pieces.changed().into_iter().map(|stretch| Net { at: stretch.gone.start, width: stretch.gone.end - stretch.gone.start, new: stretch.new }).collect()
}

/// The addresses a landed frame minted its bytes at.
///
/// The board mints a frame's values in the frame's order under one
/// frontier, and its acknowledgment names the first.
struct Minted<'n> {
    /// The frame's changes.
    net: &'n [Net],
    /// The components of the first address before its last.
    prefix: String,
    /// The last component of the first address.
    first: u64,
}

impl<'n> Minted<'n> {
    /// Returns the addresses of the frame of `net` acknowledged at `addr`,
    /// its first minted address; none where `addr` is no I-address.
    fn of(net: &'n [Net], addr: &str) -> Option<Minted<'n>> {
        let (prefix, last) = addr.rsplit_once('.')?;
        Some(Minted { net, prefix: prefix.to_string(), first: last.parse().ok()? })
    }

    /// Returns the address of the byte at `position` of the text the call
    /// leaves, where the frame minted it.
    ///
    /// It is the first address plus the bytes the changes before the byte's
    /// own mint, and the bytes of its own before it.
    fn address(&self, position: u64) -> Option<String> {
        let mut before = 0u64;
        for change in self.net {
            if change.new.contains(&position) {
                let ordinal = self.first.checked_add(before)?.checked_add(position - change.new.start)?;
                return Some(format!("{}.{ordinal}", self.prefix));
            }
            before = before.checked_add(change.minted())?;
        }
        None
    }
}

/// Returns the answer of a call that landed.
///
/// Each pair's list names its changes of `plan`, none for a pair that
/// changed nothing, each with the call's commit `at` where one is known and
/// the address its new bytes were minted at where they stand whole in the
/// text the call leaves and `minted` names the frame's addresses; `drawn`
/// is the rows of that text.
fn edited(doc: &str, plan: &Plan<'_>, pairs: usize, at: Option<u64>, minted: Option<&Minted<'_>>, drawn: Rows) -> Answer {
    let mut lists = vec![Vec::new(); pairs];
    for (k, planned) in plan.changes.iter().enumerate() {
        let Edit { ordinal, removed, inserted } = &planned.edit;
        let mut change = json!({"ordinal": ordinal.to_string(), "removed": removed.to_string(), "inserted": inserted.len().to_string()});
        let standing = plan.standing.iter().find(|run| run.planned == k);
        if let Some(addr) = standing.zip(minted).and_then(|(run, minted)| minted.address(run.at)) {
            change["addr"] = Value::from(addr);
        }
        if let Some(at) = at {
            change["at"] = Value::from(at);
        }
        lists[planned.pair].push(change);
    }
    let Rows { lines, masked } = drawn;
    let mut value = json!({"outcome": "edited", "doc": doc, "pairs": lists, "lines": lines});
    if let Some(at) = at {
        value["at"] = Value::from(at);
    }
    if masked {
        value["masked"] = Value::Bool(true);
    }
    Answer::data(value)
}

/// Makes the edits `asked` through `calls`.
///
/// In order: the draft's text is read, a published document refused before
/// any of its text is (`read_draft`); every pair is checked and the changes
/// planned ([`plan`]); the call's net changes are cut ([`net`]) and held to
/// the frame's two caps; and they are written, one `edit` frame typed
/// against the read (`send_edit`), a call that lands answered with the rows
/// of the planned text (`rows::rows`). Nothing is written before every
/// refusal a read alone decides (SP-8), and a call whose pairs leave the
/// text as it was read writes nothing and answers `unchanged`.
///
/// # Errors
///
/// The call's own answer, nothing written: [`plan`]'s; `too_large` naming
/// `new` where the call's new bytes together pass [`MAX_NEW_BYTES`], and
/// naming `changes` where its net changes are more than one frame lists
/// ([`MAX_WIRE_LIST`]). The board's verdict on a read, or the shell's
/// refusal of it; and the `op` row's refusal of the write, nothing written
/// (`send_edit`). Every other outcome is an [`Answer`].
pub(super) fn edit(calls: &impl Calls, asked: &Asked<'_>) -> Result<Answer, Refusal> {
    let doc = asked.doc;
    let Read { mut text, as_of } = match read_draft(calls, doc)? {
        Ok(read) => read,
        Err(answer) => return Ok(answer),
    };
    let plan = match plan(doc, &mut text, as_of, &asked.pairs) {
        Ok(plan) => plan,
        Err(answer) => return Ok(answer),
    };
    let net = net(&plan.pieces);
    if net.is_empty() {
        return Ok(Answer::data(json!({"outcome": "unchanged", "doc": doc, "as_of": as_of})));
    }
    if net.len() > MAX_WIRE_LIST {
        return Ok(refused(doc, "too_large", json!({"what": "changes", "changes": net.len().to_string(), "cap": MAX_WIRE_LIST.to_string()})));
    }
    let bytes = net.iter().fold(0u64, |sum, change| sum.saturating_add(change.minted()));
    if bytes > MAX_NEW_BYTES as u64 {
        return Ok(refused(doc, "too_large", json!({"what": "new", "bytes": bytes.to_string(), "cap": MAX_NEW_BYTES.to_string()})));
    }
    let changes: Vec<Value> = net.iter().map(|change| change.frame(&text)).collect();
    let pairs = asked.pairs.len();
    Ok(match send_edit(calls, doc, &changes, as_of)? {
        Landing::Acked(ack) => {
            let minted = ack["addr"].as_str().and_then(|addr| Minted::of(&net, addr));
            edited(doc, &plan, pairs, ack["at"].as_u64(), minted.as_ref(), rows(&text, &plan.pieces))
        }
        Landing::Found(at) => edited(doc, &plan, pairs, Some(at), None, rows(&text, &plan.pieces)),
        Landing::Refused(verdict) => refused_write(doc, "refused", Some(verdict)),
        Landing::Lost(lost) => answer_lost(doc, as_of, &lost),
    })
}

#[cfg(test)]
mod tests;
