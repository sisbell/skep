//! `text.edit`: several text edits of a draft in one call (skep #1079).
//!
//! A caller changes a draft as a list of exact edits — "replace this text
//! with that, and that with this" — and hands the list over in one call,
//! `text.edit(session, {doc, edits: [{old, new}, …]})`, the `text` family's
//! second, which lands all of them or none. The module makes each pair as
//! `text.replace` makes its one, out of the parent's own pieces — its read,
//! its text, its writes and the lines it settles, under the session the
//! call stands under — and adds three things to them.
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
//! the identity it had, and a link on it still follows. Each change is
//! written by position from the one read, with no find and no read between
//! two writes: its ordinal is its pair's place and its own place in the
//! pair's new text, the changes before it in the pair made by then. A
//! change that only inserts or only removes is one write, and one that does
//! both is two — the new bytes inserted after the old, the old then removed
//! — as `text.replace` writes one. The first write is typed against the
//! read's position and each later one against the commit of the write
//! before it, so a write of the call lands only on the draft as the call's
//! own writes left it.
//!
//! **All or nothing** ([`Writing`]). The draft's whole image is read before
//! the first write ([`image_runs`]); the first write, typed against the
//! text's read, lands only where the image is still the draft's. A write
//! past the first that does not land, for any cause but another writer's,
//! is answered by one `set_arrangement` of that image, the take-back, typed
//! against the commit of the call's last landed write: every byte stands at
//! its own address again, and the call answers the refusal that stopped it,
//! nothing standing. The take-back goes through the `op` row as every write
//! of the call does, once, and is never typed afresh, so it lands over no
//! other writer's change: where the board refused the write as typed
//! against an older state — another writer's change landed between two of
//! the call's — none is sent, and where the take-back does not land itself,
//! it is not sent again. The call then answers `partial`, an error naming
//! each change that stands (`stands`), and what stopped the take-back
//! (`take_back`), the changes named as ones that may stand (`may_stand`)
//! where its answer was lost. A change whose new bytes landed and whose old
//! ones were not removed is taken back by identity wherever the draft was
//! not set back, as `text.replace` takes its insert back (`undo`), and
//! named with both spans where that does not land either. The take-back is
//! a whole-draft write the shell's held-lines gate does not read, a frame
//! naming no draft to the door: the call sends it only while no line of its
//! own stands held, and answers `held` instead where one does. A write that
//! landed with no commit the shell read — an ack naming none, or a line
//! whose drop found its write landed — ends the call there, nothing written
//! after it and nothing taken back, there being no commit to type either
//! against; where it is the call's last write the call landed whole, that
//! change's commit unnamed.
//!
//! **The answer.** One JSON object keyed by `outcome`, as `text.replace`'s
//! is: `edited`, each pair's changes in the pairs' order; `unchanged`;
//! `refused`, nothing standing; and the two errors that name what stands,
//! `partial` and `held` (`shapes`' `TextEdited`, `TextEditUnchanged`,
//! `TextRefused`, `TextEditPartial`, `TextEditHeld`). A change is named by
//! its ordinal in the draft as the changes before it left it, the bytes it
//! removed and inserted, the I-address its new bytes were minted at and its
//! own commit, so a caller finds what stands by identity whatever was
//! written after it.

use serde_json::{json, Value};
use skep_client::address::is_address_text;
use skep_client::board::frames;
use skep_client::merge::origin_of;
use skep_client::text::minimal_changes;

use super::{
    held, natural, read_draft, refused, refused_write, settle, spans, undo, unread, write, Answer, Calls, Edit, Found, Line, Read, Settled, Text, Undone, Wrote, MAX_NEW_BYTES, WHOLE_CONTENT,
};
use crate::attest::MAX_WIRE_LIST;
use crate::hold::may_have_landed;
use crate::refusal::Refusal;

/// One pair of the call's: the text to replace, and its replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pair<'a> {
    /// The text to replace, not empty.
    old: &'a str,
    /// The text to stand in its place, empty where `old` is only removed.
    new: &'a str,
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
    /// The edit, its ordinal in the draft as the changes before it leave it.
    edit: Edit<'a>,
}

/// Plans the call's writes: every pair checked, and made its changes.
///
/// Each pair's `old` is found in `text` as the pairs before it leave it,
/// its minimal changes placed from where it stands, and `text` made to read
/// as the pair leaves it. `as_of` is the position `text` was read at.
/// Nothing is written.
///
/// # Errors
///
/// The call's own answer for the first pair that fails, naming it (`pair`):
/// `not_found`, `not_unique` with the count and `crosses_atom` with the
/// value that is no text, each as `text.replace` answers it, the ordinal a
/// place in the text as the pairs before leave it; and `too_large` naming
/// the change (`change`) whose new bytes pass [`MAX_NEW_BYTES`].
fn plan<'a>(doc: &str, text: &mut Text, as_of: u64, pairs: &[Pair<'a>]) -> Result<Vec<Planned<'a>>, Answer> {
    let mut plan = Vec::new();
    for (k, pair) in pairs.iter().enumerate() {
        let found = match text.find(pair.old.as_bytes()) {
            Found::Once(ordinal) => ordinal,
            Found::Nowhere => return Err(refused(doc, "not_found", json!({"count": 0, "as_of": as_of, "pair": k}))),
            Found::Many(count) => return Err(refused(doc, "not_unique", json!({"count": count, "as_of": as_of, "pair": k}))),
            Found::Across { ordinal, kind } => return Err(refused(doc, "crosses_atom", json!({"ordinal": ordinal.to_string(), "kind": kind, "as_of": as_of, "pair": k}))),
        };
        for (j, change) in minimal_changes(pair.old, pair.new).into_iter().enumerate() {
            let inserted = &pair.new[change.new.clone()];
            if inserted.len() > MAX_NEW_BYTES {
                return Err(refused(doc, "too_large", json!({"what": "new", "bytes": inserted.len().to_string(), "cap": MAX_NEW_BYTES.to_string(), "pair": k, "change": j})));
            }
            // The changes before this one in the pair are made by its turn:
            // up to its first byte the pair's stretch reads as its new text.
            let edit = Edit { ordinal: found.saturating_add(change.new.start as u64), removed: change.old.len() as u64, inserted };
            plan.push(Planned { pair: k, change: j, edit });
        }
        text.splice(found, pair.old.len(), pair.new.as_bytes());
    }
    Ok(plan)
}

/// Reads the draft's whole image as the runs a take-back sets it back to.
///
/// Each run of the image is a run of the write: its first I-address, its
/// width, and its origin by the client's own rule
/// (`skep_client::merge::origin_of`).
///
/// # Errors
///
/// The inner error is the call's own answer, nothing written: `too_large`
/// naming `runs` where the board answers `image_too_large` or the image
/// holds more runs than one write names ([`MAX_WIRE_LIST`]), and `unread`
/// naming `image` for an answer that lists no runs, a run that does not
/// read, or one whose address names no origin (SP-14). The outer one is the
/// board's or the shell's refusal of the read.
fn image_runs(calls: &impl Calls, doc: &str) -> Result<Result<Vec<Value>, Answer>, Refusal> {
    let too_large = |runs: Option<usize>| {
        let mut detail = json!({"what": "runs", "cap": MAX_WIRE_LIST.to_string()});
        if let Some(runs) = runs {
            detail["runs"] = Value::from(runs.to_string());
        }
        refused(doc, "too_large", detail)
    };
    let image = match calls.op(frames::image(doc, 1, WHOLE_CONTENT)) {
        Ok(image) => image,
        Err(Refusal::Board(refusal)) if refusal.code == "image_too_large" => return Ok(Err(too_large(None))),
        Err(refusal) => return Err(refusal),
    };
    let Some(listed) = image["runs"].as_array() else { return Ok(Err(unread(doc, "image"))) };
    if listed.len() > MAX_WIRE_LIST {
        return Ok(Err(too_large(Some(listed.len()))));
    }
    let mut runs = Vec::with_capacity(listed.len());
    for run in listed {
        let Some((i_start, width)) = run["i_start"].as_str().zip(natural(&run["width"])) else { return Ok(Err(unread(doc, "image"))) };
        let Some(origin) = origin_of(i_start) else { return Ok(Err(unread(doc, "image"))) };
        runs.push(frames::shot_run(&origin.to_string(), i_start, width));
    }
    Ok(Ok(runs))
}

/// A change of the call's that landed whole.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Made {
    /// The index of its pair in the call's `edits`.
    pair: usize,
    /// Its index among its pair's changes.
    change: usize,
    /// The ordinal of its first byte.
    ///
    /// It is a place in the draft as the changes before it left it.
    ordinal: u64,
    /// How many bytes it removed.
    removed: u64,
    /// How many bytes it inserted.
    inserted: usize,
    /// The first I-address of its new bytes.
    ///
    /// It is named where the change inserted any and its insert's ack named
    /// one.
    addr: Option<String>,
    /// The commit it was whole at, where its last write's answer named one.
    at: Option<u64>,
}

impl Made {
    /// Returns the change `planned` as landed, with what its acks named.
    fn of(planned: &Planned<'_>, addr: Option<&str>, at: Option<u64>) -> Made {
        let Planned { pair, change, edit } = planned;
        Made { pair: *pair, change: *change, ordinal: edit.ordinal, removed: edit.removed, inserted: edit.inserted.len(), addr: addr.map(str::to_string), at }
    }

    /// Returns the change as a pair's list names it (`TextEditChange`).
    fn value(&self) -> Value {
        let mut value = json!({"ordinal": self.ordinal.to_string(), "removed": self.removed.to_string(), "inserted": self.inserted.to_string()});
        if let Some(addr) = &self.addr {
            value["addr"] = Value::from(addr.as_str());
        }
        if let Some(at) = self.at {
            value["at"] = Value::from(at);
        }
        value
    }

    /// Returns the change as `stands` names it (`TextEditStanding`).
    fn standing(&self) -> Value {
        let mut value = self.value();
        value["pair"] = Value::from(self.pair);
        value["change"] = Value::from(self.change);
        value
    }
}

/// Returns a change in part as `stands` names it (`TextEditHalf`).
///
/// It is the change of two writes `planned`, by its two spans as its insert
/// left them (`spans`): the new bytes after the old ones, with the address
/// and the commit of `inserted`, the insert's ack, where it landed with
/// one.
fn half(planned: &Planned<'_>, inserted: Option<&Value>) -> Value {
    let mut value = spans(&planned.edit, inserted);
    value["pair"] = Value::from(planned.pair);
    value["change"] = Value::from(planned.change);
    value
}

/// A write of the call's that did not land, and nothing of it is queued.
#[derive(Debug)]
enum Failed {
    /// Its line was dropped.
    ///
    /// It carries the hold's cause, and the board's verdict where it gave
    /// one.
    Dropped {
        /// The held cause.
        cause: String,
        /// The board's verdict on the write.
        verdict: Option<Value>,
    },
    /// The `op` row refused it, nothing held.
    Refused(Refusal),
}

impl Failed {
    /// Returns whether another writer's change stopped the write.
    ///
    /// The board refused it as typed against an older state: a change
    /// landed since the write before.
    fn moved(&self) -> bool {
        match self {
            Failed::Dropped { cause, verdict } => cause == "moved" || verdict.as_ref().is_some_and(|verdict| verdict["code"] == "arrangement_moved"),
            Failed::Refused(_) => false,
        }
    }

    /// Returns what stopped the write, as a `partial` says it.
    ///
    /// It is the `cause`, and the `refusal` beside it where there is one.
    fn why(&self) -> Value {
        match self {
            Failed::Dropped { cause, verdict: Some(verdict) } => json!({"cause": verdict["code"].as_str().unwrap_or(cause), "refusal": verdict}),
            Failed::Dropped { cause, verdict: None } => json!({"cause": cause}),
            Failed::Refused(refusal) => json!({"cause": refusal.name(), "refusal": refusal.to_value()}),
        }
    }

    /// Returns the call's answer where nothing of it stands.
    ///
    /// It is the refusal of the write of `planned` that did not land.
    ///
    /// # Errors
    ///
    /// The `op` row's refusal, where the row refused the write.
    fn answer(self, doc: &str, planned: &Planned<'_>) -> Result<Answer, Refusal> {
        match self {
            Failed::Dropped { cause, verdict } => {
                let mut answer = refused_write(doc, &cause, verdict);
                answer.value["pair"] = Value::from(planned.pair);
                answer.value["change"] = Value::from(planned.change);
                Ok(answer)
            }
            Failed::Refused(refusal) => Err(refusal),
        }
    }
}

/// What became of one write of the call's.
#[derive(Debug)]
enum Sent {
    /// It landed, and its ack names what the call goes on by.
    Landed {
        /// The board's ack.
        ack: Value,
        /// The ack's commit, which the next write is typed against.
        at: u64,
    },
    /// It landed with no commit the shell read.
    ///
    /// Its ack names none, or no address where the call needs one
    /// (`unread`, the ack beside it), or its line's drop found it landed,
    /// its own answer lost (`answer_lost`).
    Unnamed {
        /// `unread` or `answer_lost`.
        cause: &'static str,
        /// The ack, where the board gave one.
        ack: Option<Value>,
    },
    /// It did not land.
    Failed(Failed),
    /// Its line stays held: the shell would not drop it, and it may land.
    Standing(Line),
}

/// The call's writes as they land.
///
/// It holds the take-back's runs, the position the next write is typed
/// against, and the changes made whole so far.
struct Writing<'c, C> {
    /// The calls the writes go through.
    calls: &'c C,
    /// The draft.
    doc: &'c str,
    /// The draft's image as read before the first write, a take-back's runs.
    runs: Vec<Value>,
    /// The position the next write is typed against.
    ///
    /// It is the text's read, then the commit of the last landed write.
    typed: u64,
    /// The changes landed whole, in write order.
    made: Vec<Made>,
}

impl<C: Calls> Writing<'_, C> {
    /// Writes `plan`, each change in its order, and answers the call.
    ///
    /// `pairs` is how many pairs the call was asked: the answer of a call
    /// that landed whole lists each pair's changes, none for a pair that
    /// changed nothing.
    ///
    /// # Errors
    ///
    /// The `op` row's refusal of a write that left nothing standing: the
    /// first, or a later one where the take-back landed.
    fn all(mut self, plan: &[Planned<'_>], pairs: usize) -> Result<Answer, Refusal> {
        for (k, planned) in plan.iter().enumerate() {
            if let Some(ended) = self.change(planned, k + 1 == plan.len()) {
                return ended;
            }
        }
        let mut lists = vec![Vec::new(); pairs];
        for made in &self.made {
            lists[made.pair].push(made.value());
        }
        let mut value = json!({"outcome": "edited", "doc": self.doc, "pairs": lists});
        if let Some(at) = self.made.last().and_then(|made| made.at) {
            value["at"] = Value::from(at);
        }
        Ok(Answer::data(value))
    }

    /// Writes one change, and answers where the call ends at it.
    ///
    /// The new bytes are inserted first where the change has any, after the
    /// old ones, then the old ones removed where it has any, each write
    /// typed against the commit of the one before. `last` says the change is
    /// the plan's last: a last write that landed with no commit read is the
    /// call landed whole, that change's commit unnamed.
    fn change(&mut self, planned: &Planned<'_>, last: bool) -> Option<Result<Answer, Refusal>> {
        let edit = &planned.edit;
        let two = edit.removed > 0 && !edit.inserted.is_empty();
        let mut inserted = None;
        if !edit.inserted.is_empty() {
            match self.send(frames::insert_text(self.doc, edit.after(), edit.inserted, self.typed, None), two) {
                Sent::Landed { ack, at } => {
                    self.typed = at;
                    inserted = Some(ack);
                }
                Sent::Unnamed { cause, .. } if two => return Some(Ok(self.partial(planned, json!({"cause": cause, "op": "insert"}), Some(half(planned, None)), None))),
                Sent::Unnamed { cause, ack } => {
                    self.made.push(Made::of(planned, ack.as_ref().and_then(|ack| ack["addr"].as_str()), None));
                    return (!last).then(|| Ok(self.partial(planned, json!({"cause": cause, "op": "insert"}), None, None)));
                }
                Sent::Failed(failed) => return Some(self.failed(planned, failed, None)),
                Sent::Standing(line) => return Some(Ok(self.held_at(planned, &line, "insert", two.then(|| half(planned, None))))),
            }
        }
        let addr = inserted.as_ref().and_then(|ack| ack["addr"].as_str());
        if edit.removed == 0 {
            self.made.push(Made::of(planned, addr, Some(self.typed)));
            return None;
        }
        match self.send(frames::delete(self.doc, edit.ordinal, edit.removed, self.typed, None), false) {
            Sent::Landed { at, .. } => {
                self.typed = at;
                self.made.push(Made::of(planned, addr, Some(at)));
                None
            }
            Sent::Unnamed { cause, .. } => {
                self.made.push(Made::of(planned, addr, None));
                (!last).then(|| Ok(self.partial(planned, json!({"cause": cause, "op": "delete"}), None, None)))
            }
            Sent::Failed(failed) => Some(self.failed(planned, failed, inserted.as_ref())),
            Sent::Standing(line) => Some(Ok(self.held_at(planned, &line, "delete", inserted.as_ref().map(|ack| half(planned, Some(ack)))))),
        }
    }

    /// Sends one write of the call's, and reads what became of it.
    ///
    /// A held line is settled first (`settle`), so none of the call's is
    /// left queued but one the shell would not drop. `needs_addr` says the
    /// write is the insert of a change of two writes, whose ack must name
    /// the address its bytes were minted at for the change to be taken back
    /// by identity.
    fn send(&self, frame: Value, needs_addr: bool) -> Sent {
        match write(self.calls, frame) {
            Ok(Wrote::Acked(ack)) => match ack["at"].as_u64().filter(|_| !needs_addr || ack["addr"].is_string()) {
                Some(at) => Sent::Landed { ack, at },
                None => Sent::Unnamed { cause: "unread", ack: Some(ack) },
            },
            Ok(Wrote::Held(line)) => match settle(self.calls, line) {
                Settled::Landed => Sent::Unnamed { cause: "answer_lost", ack: None },
                Settled::Dropped { cause, verdict } => Sent::Failed(Failed::Dropped { cause, verdict }),
                Settled::Standing(line) => Sent::Standing(line),
            },
            Err(refusal) => Sent::Failed(Failed::Refused(refusal)),
        }
    }

    /// Answers a write of `planned` that did not land.
    ///
    /// `inserted` is the ack of the change's own insert, where the write is
    /// the removal after it. The first write of the call leaves nothing, and
    /// its refusal is the answer. Past it, the draft is set back to the
    /// image read before the first write by one `set_arrangement` typed
    /// against the commit of the last landed write — unless the board
    /// refused the write as typed against an older state, another writer's
    /// change standing in the draft, which nothing is taken back over. Where
    /// the draft was not set back, a change in part is taken back by
    /// identity (`undo`), and the answer names each change that stands:
    /// `partial`, or `held` naming the undo's line where the shell would not
    /// drop it.
    ///
    /// # Errors
    ///
    /// The `op` row's refusal of the write, where nothing of the call
    /// stands.
    fn failed(&mut self, planned: &Planned<'_>, failed: Failed, inserted: Option<&Value>) -> Result<Answer, Refusal> {
        if self.made.is_empty() && inserted.is_none() {
            return failed.answer(self.doc, planned);
        }
        let take_back = if failed.moved() {
            None
        } else {
            match self.calls.op(frames::set_arrangement(self.doc, &self.runs, self.typed, None, None, None, None)) {
                Ok(_) => return failed.answer(self.doc, planned),
                Err(refusal) => Some(refusal),
            }
        };
        let mut in_part = None;
        if let Some(ack) = inserted {
            match undo(self.calls, self.doc, ack["addr"].as_str().unwrap_or_default(), planned.edit.inserted.len() as u64) {
                Undone::Gone => {}
                Undone::Stands => in_part = Some(half(planned, Some(ack))),
                Undone::Held(line) => return Ok(self.held_at(planned, &line, "undo", Some(half(planned, Some(ack))))),
            }
        }
        if self.made.is_empty() && in_part.is_none() {
            return failed.answer(self.doc, planned);
        }
        Ok(self.partial(planned, failed.why(), in_part, take_back))
    }

    /// Returns the changes that stand, as `stands` lists them.
    ///
    /// They are each change landed whole, in write order, then `in_part`,
    /// the change the call stopped in.
    fn stands(&self, in_part: Option<Value>) -> Vec<Value> {
        self.made.iter().map(Made::standing).chain(in_part).collect()
    }

    /// Returns the answer of a call that landed in part, an error.
    ///
    /// The call stopped at the change `planned`; `why` says what stopped it
    /// — a `cause`, and the `refusal` beside it or the `op` whose answer the
    /// shell did not read — and `in_part` is that change where its new bytes
    /// stand beside its old ones. `take_back` is the refusal of a take-back
    /// that was sent and did not land; where its answer was lost the
    /// take-back may have landed, and the changes are named as ones that
    /// may stand (`may_stand`).
    fn partial(&self, planned: &Planned<'_>, why: Value, in_part: Option<Value>, take_back: Option<Refusal>) -> Answer {
        let mut value = json!({"outcome": "partial", "doc": self.doc, "pair": planned.pair, "change": planned.change, "stands": self.stands(in_part)});
        if let (Some(members), Value::Object(why)) = (value.as_object_mut(), why) {
            members.extend(why);
        }
        if let Some(refusal) = take_back {
            value["take_back"] = json!({"cause": refusal.name(), "refusal": refusal.to_value()});
            if may_have_landed(&refusal) {
                value["may_stand"] = Value::Bool(true);
            }
        }
        Answer::error(value)
    }

    /// Returns the answer of a call a line of which stays held, an error.
    ///
    /// `line` is the line, of the change `planned`, and `write` the write it
    /// is: `insert`, `delete`, or `undo`, the removal of a change's new
    /// bytes. `in_part` is that change by its two spans where it is of two
    /// writes, of which the one the line would place or remove may or may
    /// not stand.
    fn held_at(&self, planned: &Planned<'_>, line: &Line, write: &str, in_part: Option<Value>) -> Answer {
        held(self.doc, line, write, json!({"pair": planned.pair, "change": planned.change, "stands": self.stands(in_part)}))
    }
}

/// Makes the edits `asked` through `calls`.
///
/// In order: the draft's text is read, a published document refused before
/// any of its text is (`read_draft`); every pair is checked and the writes
/// planned ([`plan`]); the draft's image is read ([`image_runs`]); and the
/// changes are written ([`Writing::all`]). Nothing is written before every
/// refusal a read alone decides (SP-8), and a call whose pairs change
/// nothing reads no image and answers `unchanged`.
///
/// # Errors
///
/// The board's verdict on a read, or the shell's refusal of it; and the
/// `op` row's refusal of a write that left nothing standing. Every other
/// outcome is an [`Answer`].
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
    if plan.is_empty() {
        return Ok(Answer::data(json!({"outcome": "unchanged", "doc": doc, "as_of": as_of})));
    }
    let runs = match image_runs(calls, doc)? {
        Ok(runs) => runs,
        Err(answer) => return Ok(answer),
    };
    Writing { calls, doc, runs, typed: as_of, made: Vec::new() }.all(&plan, asked.pairs.len())
}

#[cfg(test)]
mod tests;
