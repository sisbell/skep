//! THE PIN (F8): a sample of every declared type, built as the crate's code
//! builds it, round-tripped through `serde_json` and its field names held
//! equal to the table's — every required field present, no field outside
//! the table — so a field renamed in the declaration alone, or in the code
//! alone, fails here; and the file names every shape, every call and every
//! event, the refusal union naming the held-lines refusal whole beside the
//! shell's open one.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use skep_client::halt::{Blocked, Face, Refused};
use skep_client::search::{Range, State};
use skep_client::DialError;

use super::*;
use crate::feed::{answer_without_index, places_without_index, state_json};
use crate::refusal::{Name, Refusal};
use crate::sessions;

/// One sample per declared type: the value the crate's code answers or
/// emits for it — the refusals through `Refusal::to_value`, the search
/// answer through `feed::answer_without_index`, the listing through
/// `feed::places_without_index`, the index state through `feed::state_json`,
/// the death through `sessions`, the rest in the shape `shell`'s and its
/// rows' children's `json!` spell (the publication family's, the merge
/// family's and the restore's answers are held to their declarations
/// against the real board by the shell's own suite,
/// `shell/tests/publication.rs`, `merge.rs` and `history.rs`).
fn samples() -> Vec<(&'static str, Value)> {
    let facts = json!({"principal": 1, "account": "1.0.1", "origin": "http://127.0.0.1:8642"});
    vec![
        ("BoardRow", json!({"board": "b-0", "name": "http://127.0.0.1:8642", "origin": "http://127.0.0.1:8642"})),
        ("SessionOpened", json!({"session": "s-0", "principal": 1, "account": "1.0.1", "writes": true, "opened_at": 5, "another_window": true})),
        ("Keygen", json!({"fingerprint": "ab", "payload": "{}", "outstanding": "x"})),
        ("FingerprintRow", json!({"fingerprint": "ab", "label": "phone", "bindings": [], "unbound": true, "payload": null})),
        ("Claimed", json!({"account": "1.0.1", "principal": 1, "fingerprint": "ab", "agent_space": "1.0.1.1", "display_name": null, "warnings": []})),
        ("Facts", facts.clone()),
        ("Enrolled", json!({"facts": facts, "fingerprints": ["ab"], "reconciled": false, "warnings": []})),
        ("Bound", json!({"warning": "w", "warnings": []})),
        ("Recovered", json!({"facts": facts, "enrolled": [], "retired": [], "containment": false, "recovery_read": [], "warnings": []})),
        ("Rotated", json!({"facts": facts, "old": "ab", "new": "cd", "trail": "1.0.1.0.1.0.2.3", "warnings": []})),
        ("HandoffDelegated", json!({"address": "1.0.1.2", "principal": 7, "already": false})),
        ("Accepted", json!({"payload": "{}"})),
        ("Health", json!({"health": {"ok": true}, "mode": "UNCLAIMED"})),
        ("Probe", json!({"daemon": "running", "dialed": "http://127.0.0.1:8642", "signed": "http://127.0.0.1:8642"})),
        ("SearchAnswer", answer_without_index()),
        ("Hit", json!({"doc": "1.0.1.0.1", "member": null, "as_of": 3, "span": {"start": 1, "width": 5}, "score": 1.5, "snippet": null, "kind": "edition", "standing": "public", "occurrences": 1, "matched": []})),
        ("SpanText", json!({"start": 1, "width": 5})),
        ("Snippet", json!({"text": "t", "start": 1, "marks": []})),
        ("Mark", json!({"offset": 0, "len": 1, "kind": {"span": true}})),
        ("Matched", json!({"word": "w", "term": "t"})),
        ("Place", json!({"doc": "1.0.1.0.1", "kind": "draft", "label": null, "standing": "yours_to_read"})),
        ("PlacesAnswer", places_without_index()),
        ("AccountCount", json!({"account": "1.0.1", "documents": 2})),
        ("ChangesAnswer", json!({"entries": [{"position": 3, "at": 3, "op": "insert", "docs": ["1.0.1.0.1"], "class": "published", "key": "bare", "time": 1}], "next": 3, "head": 3})),
        ("RefusedByBoard", Refusal::Board(Refused { status: 200, code: "credential_refused".into(), detail: Some("signed_session_required".into()), op: Some("publish".into()), body: json!({}) }).to_value()),
        ("HaltFace", Refusal::named(Name::NO_KEY, Face { state: "s".into(), cause: "c".into(), act: "a".into(), path: Some("/a/store".into()) }).to_value()),
        ("BlockedFace", Refusal::Blocked(Blocked { record: "1.0.1.0.7.1".into(), named_by: "http://x".into(), ground: None }).to_value()),
        ("Unreachable", Refusal::Unreachable(DialError::Connect("refused".into())).to_value()),
        ("HeldLinesRefusal", Refusal::shell(Name::HELD_LINES, json!({"doc": "1.0.1.0.5", "held": 2})).to_value()),
        ("ShellRefusal", Refusal::shell(Name::SESSION_ENDED, json!({})).to_value()),
        ("ModeEvent", json!({"board": "b-0", "mode": "ENFORCING", "claimant": "1.0.1", "local_trust": false})),
        ("SessionDiedEvent", json!({"session": "s-0", "reason": sessions::closed()})),
        ("DeathReason", sessions::closed()),
        ("DaemonEvent", json!({"board": "b-0", "state": "running"})),
        ("FeedEvent", json!({"board": "b-0", "update": {"position": 3, "at": 3, "op": "insert", "docs": ["1.0.1.0.1"], "class": "published", "key": "bare", "time": 1}})),
        ("FeedUpdate", json!({"position": 3, "at": 3, "op": "insert", "docs": ["1.0.1.0.1"], "class": "drafts", "session": "s-0", "key": "bare", "time": 1, "attest": null, "new_prefix": "1.0.2", "new_id": 2, "link": "1.0.1.0.1.0.2.1", "placed": "3", "base_extent": null})),
        ("IndexEvent", json!({"board": "b-0", "session": null, "state": state_json(&State::None)})),
        ("IndexState", state_json(&State::Widening { range: Range::Board })),
        ("MomentEvent", json!({"id": "m-0", "kind": "label", "data": {}, "walk": "claim", "board": "b-0", "answerable": true})),
        ("Answer", json!({"id": "m-0", "value": "phone"})),
        ("Cancel", json!({"id": "m-0"})),
        ("HeldAnswer", json!({"resp": "held", "held": 1, "cause": "unreachable", "unwritable": "No space left on device (os error 28)", "unwritable_class": "full"})),
        ("HeldRow", json!({"held": 1, "doc": "1.0.1.0.1", "base": 5, "frame": {"op": "delete"}, "anchors": {"before": "1.0.1.0.1.0.1.3", "after": null, "span": [{"start": "1.0.1.0.1.0.1.4", "width": "2"}]}, "cause": "unreachable", "sent": false, "time": 1})),
        ("Anchors", crate::held::Anchors::of(&json!({"before": "1.0.1.0.1.0.1.3", "after": null, "span": [{"start": "1.0.1.0.1.0.1.4", "width": "2"}]})).expect("the anchors' form").json()),
        ("BurstPiece", json!({"burst": "b-1", "offset": 6, "width": 5})),
        ("HeldEvent", json!({"board": "b-0", "session": "s-0", "doc": "1.0.1.0.1", "held": 2, "state": "moved", "hands": [{"key": "bare"}]})),
        ("Hand", json!({"key": "other", "fingerprint": "ab", "label": "phone"})),
        ("Resolve", json!({"session": "s-0", "held": 1, "act": "drop"})),
        ("AnotherWindowEvent", json!({"board": "b-0", "another_window": true})),
        ("Run", json!({"origin": "1.0.1.0.5", "i_start": 1, "width": 10})),
        (
            "PublicationPanel",
            json!({"rows": [], "formatting": {"marks": [], "cut": 0, "removals": []}, "read_with": {"1.0.1.0.3": true}, "count": {"l": 0, "n": 0, "r": 0, "e": 0, "claim": false, "read_with": []}, "price": {"lists": [0, 0, 0, 0, 0, 0], "body": 0, "values": 0, "reads": 0, "bytes": 0, "over": []}, "windows": [], "parts": [], "inherited": [{"draft": "1.0.1.0.9", "passages": 2}], "merge_records": [{"draft": "1.0.1.0.11", "n": 2}], "edition_links": 1, "p3_stands": true, "standing": "at_head", "left_behind": ["1.0.1.0.9"], "hold": {"since": 1}}),
        ),
        ("PublicationRow", json!({"home": "1.0.1.0.5", "kind": {"public": {"read_with": false}}, "label": "notes here", "links": ["1.0.1.0.5.0.2.1"], "types": [], "line": {"p": 0, "d": 0, "c": 0, "t": 0, "u": 0}, "read_through": 0, "unchanged": ["1.0.1.0.5.0.2.1"], "fold": {"unchanged": 1, "changed": 0}, "changed_types": [], "unchanged_types": []})),
        ("TypeFold", json!({"ty": "1.1.0.1.0.1.0.3.13", "n": 1, "far": ["1.0.1.0.8"]})),
        ("RowFold", json!({"unchanged": 40, "changed": 1})),
        ("RowLine", json!({"p": 1, "d": 0, "c": 0, "t": 0, "u": 0})),
        ("Formatting", json!({"marks": ["1.0.1.0.5.0.2.1"], "cut": 1, "removals": []})),
        ("Removal", json!({"record": "1.0.1.0.5.0.2.9", "mark": "1.0.1.0.2.1.0.2.1", "mark_value": {"from": [], "to": [], "ty": [], "at": 7}, "on_selection": true, "spent": false, "remake": null, "original": "1.0.1.0.5.0.2.3", "rest": [{"chain": "1.0.1.0.2.0.1", "first": 8, "width": 2}]})),
        ("LinkValue", json!({"from": [{"start": "1.0.1.0.2.0.1.5", "width": "0.0.0.0.0.0.0.5"}], "to": [], "ty": [{"start": "1.1.0.1.0.1.0.3.13", "width": "0.0.0.0.0.0.0.0.1"}], "at": 7})),
        ("LinkSpan", json!({"start": "1.0.1.0.2.0.1.5", "width": "0.0.0.0.0.0.0.5"})),
        ("Count", json!({"l": 3, "n": 2, "r": 1, "e": 0, "claim": false, "read_with": ["1.0.1.0.4"], "supersede": ["1.0.1.0.2.1.1"]})),
        ("Price", json!({"lists": [3, 1, 4, 1, 1, 0], "body": 120, "values": 10, "reads": 20, "bytes": 5000, "over": [{"term": "lists", "by": 1}]})),
        ("PriceOver", json!({"term": "links", "by": 4})),
        ("Window", json!({"run": 2, "origin": "1.0.1.0.7", "owner": "1.0.1", "i_start": 1, "width": 5, "parts": [{"part": 0, "from": {"chain": "1.0.1.0.7.0.1", "first": 1, "width": 4}, "ordinal": 30, "admits": ["counterpart", "drop"], "record": "1.0.1.0.7.0.2.1", "to": {"chain": "1.0.1.0.2.0.1", "first": 16, "width": 4}}]})),
        ("PartCounts", json!({"run": 2, "part": 0, "marks": 1, "links": 1, "kept_marks": 0})),
        ("Part", json!({"part": 1, "from": {"chain": "1.0.1.0.7.0.1", "first": 5, "width": 1}, "ordinal": 34, "admits": ["publish_first", "drop", "keep_private"]})),
        ("Inherited", json!({"draft": "1.0.1.0.9", "passages": 2})),
        ("MergeRecords", json!({"draft": "1.0.1.0.11", "n": 2})),
        ("ISpan", json!({"chain": "1.0.1.0.7.0.1", "first": 1, "width": 4})),
        ("Hold", json!({"since": 1_761_696_000_000u64})),
        ("Switches", json!({"on": ["1.0.1.0.6"], "destinations": {"1.0.1.0.6": {"set": "1.0.1.0.4"}}})),
        ("Acknowledged", json!({"outcome": "acknowledged", "member": "1.0.1.0.2.2", "edition": null, "claim": false, "supersede": ["1.0.1.0.2.1.1"], "at": 412, "via": "answer"})),
        ("Restated", json!({"outcome": "restated", "left": [], "superseded": [], "came": ["1.0.1.0.6.0.2.3"], "removals_undone": [], "removals_came": [], "selection": [{"run": 1, "placement": {"split": [[1, 2, 1], [3, 3, 1]]}}], "parts": [{"run": 2, "part": 0, "record": "1.0.1.0.7.0.2.1"}], "left_out": [{"entry": 3, "original": "1.0.1.0.6.0.2.1", "cause": "superseded"}], "race": {"at": 999, "key": "bare", "signed": false}, "base": "1.0.1.0.2.3", "standing": "behind"})),
        ("RaceKey", json!({"at": 999, "key": "bare", "signed": false})),
        ("PublicationRefused", json!({"outcome": "refused", "arm": "claim_refused", "edition": "1.0.1.0.2"})),
        ("PublicationEvent", json!({"board": "b-0", "session": "s-0", "draft": "1.0.1.0.5", "state": "acknowledged", "member": "1.0.1.0.2.2", "edition": null, "at": 412})),
        (
            "MergeReport",
            json!({"outcome": "landed", "doc": "1.0.1.0.2", "head": "1.0.1.0.2.1", "base": "1.0.1.0.2.1", "side": "1.0.1.0.2.1.1", "form": "daughter", "sides": [{"at": "1.0.1.0.2.1", "role": "head", "position": null}], "runs": [{"origin": "1.0.1.0.2", "i_start": 1, "width": 19, "side": null, "family": "own"}], "gaps": [], "counts": {"a": 1, "b": 1, "m": 1}, "cap": 4096, "over_cap": false, "record": {"type": "merge"}, "as_of": 12, "into": "1.0.1.0.5", "position": 13, "fresh": false, "head_moved": null, "record_link": "1.0.1.0.1.0.2.3", "member": "1.0.1.0.2.2", "claims": []}),
        ),
        ("MergeSide", json!({"at": "1.0.1.0.5", "role": "draft", "position": 12})),
        ("MergeRun", json!({"origin": "1.0.1.0.2", "i_start": 1, "width": 19, "side": 1, "family": "draft_native"})),
        ("MergeGap", json!({"id": 1, "kind": "order", "after": "1.0.1.0.2.0.1.4", "before": null, "runs": [{"side": 1, "i_start": "1.0.1.0.2.0.1.20", "width": 6}], "placed": [0, 1], "settled": false, "resolved_by": null})),
        ("GapRun", json!({"side": 1, "i_start": "1.0.1.0.2.0.1.20", "width": 6})),
        ("RunCounts", json!({"a": 1, "b": 2, "m": 3})),
        ("MergeLanded", json!({"outcome": "landed", "member": "1.0.1.0.2.2", "at": 412, "via": "answer", "claim": false, "supersede": ["1.0.1.0.2.1.1"], "daughter": false, "record": "1.0.1.0.1.0.2.3", "claims": ["1.0.1.0.2.0.2.1"], "retries": 0, "answers": [], "left_private": [{"set": "1.0.1.0.6", "links": 2}], "defaults": []})),
        ("WindowPart", json!({"run": 2, "part": 0, "words": "the words", "after": "and", "ordinal": 9, "origin": "1.0.1.0.7", "owner": null, "span": {"chain": "1.0.1.0.7.0.1", "first": 1, "width": 9}, "record": null, "counterpart": null, "version": null, "sides": ["1.0.1.0.2.1"], "admits": ["publish_first", "drop", "keep_private"], "answer": null, "named_since": false})),
        ("WindowMisfit", json!({"flag": "window", "key": "1.0.1.0.2.1", "published_in": []})),
        ("WindowPartsOwedRefusal", json!({"kind": "shell", "name": "window_parts_owed", "parts": [], "answers": [], "misfits": [], "left_private": [], "defaults": []})),
        ("LeftPrivate", json!({"set": "1.0.1.0.6", "links": 2})),
        ("MergeDefault", json!({"id": 1, "kind": "order", "after": null, "before": null, "placed": [0]})),
        ("Undone", json!({"draft": "1.0.1.0.5", "position": 14, "record": null, "restored": {"base": "1.0.1.0.2.1", "extent": 19}})),
        ("Withdrawn", json!({"draft": "1.0.1.0.5", "position": 14, "record": "1.0.1.0.1.0.2.4"})),
        ("Restored", json!({"draft": "1.0.1.0.5", "at": 9, "position": 16, "as_of": 15, "marker": {"sides": ["1.0.1.0.2.1.1"], "head": "1.0.1.0.2.2", "head_copied": "13", "at": 12}})),
        ("MergeMarker", json!({"sides": ["1.0.1.0.2.1.1"], "head": "1.0.1.0.2.2", "head_copied": null, "at": null})),
    ]
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().expect("an object").keys().cloned().collect()
}

/// Every declared type has a sample and every sample a declaration; each
/// sample's keys hold every required field and nothing outside the table.
#[test]
fn every_declared_type_round_trips_its_sample_against_the_table() {
    let samples = samples();
    let declared: BTreeSet<&str> = SHAPES.iter().map(|s| s.name).collect();
    let sampled: BTreeSet<&str> = samples.iter().map(|(n, _)| *n).collect();
    assert_eq!(declared, sampled, "a declared type without a sample, or a sample of no declared type");
    for (name, sample) in &samples {
        let shape = shape(name).unwrap();
        let text = serde_json::to_string(sample).unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();
        let got = keys(&back);
        let all: BTreeSet<String> = shape.fields.iter().map(|f| f.name.to_string()).collect();
        let required: BTreeSet<String> = shape.fields.iter().filter(|f| f.required).map(|f| f.name.to_string()).collect();
        assert!(required.is_subset(&got), "{name}: a required field is missing — declared {required:?}, built {got:?}");
        if !shape.open {
            assert!(got.is_subset(&all), "{name}: a built field is not declared — declared {all:?}, built {got:?}");
        }
    }
}

/// The file names every shape, every call of §4b.1, the document index's
/// listing and the change feed's page — its rows the dispatch's calls, in
/// the dispatch's order, each form of a row's argument object its members
/// in their order, the forms joined as a union and a form of no member `{}`
/// — both answers and the nine events; a field's optionality renders as
/// `?`, as the field spells itself.
#[test]
fn the_file_names_every_shape_call_and_event() {
    assert_eq!([req("position", "number").to_string(), opt("warning", "string").to_string()], ["position: number", "warning?: string"], "a field spells itself as the declarations spell it");
    let text = declarations();
    for shape in SHAPES {
        assert!(text.contains(&format!("export interface {} {{", shape.name)), "{}", shape.name);
    }
    for row in CALL_ROWS {
        assert!(text.contains(&format!("  {}(args: ", method_name(row.name))), "{}", row.name);
    }
    assert_eq!(CALL_ROWS.len(), 34, "the thirty-four calls: §4b.1's with the publication family's four, the merge family's four, `history.restore` and `held.show`, the document index's listing and the change feed's page");
    assert_eq!(CALL_ROWS.iter().map(|row| row.name).collect::<Vec<_>>(), crate::CALLS, "the declared rows are the dispatch's calls, in its order");
    for line in [
        "  boards(args: {}): Promise<Outcome<BoardRow[]>>;\n",
        "  session(args: { board: string; principal?: number }): Promise<Outcome<SessionOpened>>;\n",
        "  op(args: { session: string; frame: unknown; anchors?: Anchors; after?: string } | { guest: true; board?: string; origin?: string; frame: unknown }): Promise<Outcome<unknown>>;\n",
        "  'publication.open'(args: { session: string; draft: string; also?: string[]; doc?: string; mint?: string; claim?: boolean; selection?: Run[]; notes?: string[]; readable_drafts?: string[]; published?: string[] }): Promise<Outcome<PublicationPanel>>;\n",
        "  'publication.count'(args: { session: string; switches?: Switches; answers?: Record<string, OriginAnswer> }): Promise<Outcome<{ count: Count; price: Price; rows: PublicationRow[]; formatting: Formatting; windows: Window[]; parts: PartCounts[]; edition_links: number; p3_stands: boolean }>>;\n",
        "  'publication.confirm'(args: { session: string; switches?: Switches; answers?: Record<string, OriginAnswer> }): Promise<Outcome<Acknowledged | Restated | PublicationRefused>>;\n",
        "  'publication.cancel'(args: { session: string }): Promise<Outcome<Empty>>;\n",
        "  'merge.compose'(args: { session: string; doc: string; alternative?: string; draft?: string; into?: string }): Promise<Outcome<MergeReport>>;\n",
        "  'merge.land'(args: { session: string; resolutions?: Record<string, MergeChoice>; answers?: Record<string, OriginAnswer> }): Promise<Outcome<MergeLanded | Restated | PublicationRefused>>;\n",
        "  'merge.undo'(args: { session: string }): Promise<Outcome<Undone>>;\n",
        "  'merge.withdraw'(args: { session: string; draft: string }): Promise<Outcome<Withdrawn>>;\n",
        "  'history.restore'(args: { session: string; draft: string; at: number; as_of: number }): Promise<Outcome<Restored>>;\n",
        "  marker: MergeMarker | null;\n",
        "  head_copied: string | null;\n",
        "  'held.show'(args: { session: string }): Promise<Outcome<{ shown: boolean }>>;\n",
        "  supersede: string[];\n",
        "  over_cap: boolean;\n",
        "  unrecorded?: Refusal;\n",
        "export type MergeChoice = 'keep_both' | 'omit' | { order: number[] } | { keep_only: number } | { after: string } | { before: string };\n",
        "  places(args: { session: string; board?: string; opts?: PlacesOpts } | { guest: true; board?: string; origin?: string; opts?: PlacesOpts }): Promise<Outcome<PlacesAnswer>>;\n",
        "  changes(args: { session: string; since: number; limit?: number; class?: 'drafts' } | { guest: true; board?: string; origin?: string; since: number; limit?: number }): Promise<Outcome<ChangesAnswer>>;\n",
        "  opened_at?: number;\n",
        "  reopened?: boolean;\n",
        "export interface PlacesOpts { under?: string }\n",
        "export type OriginAnswer = 'publish_first' | 'drop' | 'keep_private' | 'counterpart';\n",
        "export type RowKind = 'own' | 'notes' | 'private' | { public: { read_with: boolean } };\n",
        "  writes: boolean;\n",
        "  entries: FeedUpdate[];\n",
        "  hands?: Hand[];\n",
        "  anchors?: Anchors;\n",
        "  standing?: BaseStanding;\n",
        "  race?: RaceKey;\n  base?: string;\n  standing?: BaseStanding;\n",
        "  left_behind: string[];\n",
        "export type BaseStanding = 'at_head' | 'behind' | 'first' | 'superseded_first';\n",
        "  before: string | null;\n",
        "  span?: { start: string; width: string }[];\n",
        "  site: { addr?: string; index?: number; operand?: 'first' | 'second'; region?: number; slot?: number; fault?: string; as_of?: number; current?: number };\n",
        "  unwritable?: string;\n  unwritable_class?: 'full' | 'read_only' | 'other';\n",
        "  opened_at?: number;\n  another_window?: true;\n",
        "export interface AnotherWindowEvent {\n  board: string;\n  another_window: boolean;\n}\n",
        "export type Refusal = RefusedByBoard | HaltFace | BlockedFace | Unreachable | HeldLinesRefusal | WindowPartsOwedRefusal | ShellRefusal;\n",
        "export interface HeldLinesRefusal {\n  kind: 'shell';\n  name: 'held_lines';\n  doc: string;\n  held: number;\n}\n",
    ] {
        assert!(text.contains(line), "the row renders as declared: {line}");
    }
    for alias in ALIASES {
        assert!(text.contains(&format!("{alias}\n")), "the alias renders ahead of the shapes: {alias}");
    }
    assert!(text.contains("  answer(args: Answer)") && text.contains("  cancel(args: Cancel)"));
    assert!(
        text.contains("export type EventName = 'mode' | 'session-died' | 'daemon' | 'feed' | 'index' | 'moment' | 'held' | 'publication' | 'another-window';\n\n"),
        "the nine event names render from the enum, in its order"
    );
    assert!(text.contains("  warning?: string;"), "an optional field renders with `?`");
    assert!(text.contains("  position: number;"), "a required field renders bare");
    let open = SHAPES.iter().filter(|s| s.open).count();
    assert_eq!(open, 5, "the shell refusal, the death's reason, the index state, the publication's refusal and its event carry their own members");
    assert_eq!(text.matches("  [member: string]: unknown;\n").count(), open, "an open shape, and it alone, renders its index signature");
    assert!(text.starts_with("// skep-shell — the bridge's declarations"));
}

/// The death's members are declared (skep #571): `session_died`'s `session`
/// and `reason`, required; and every member each arm of the reason is built
/// with — the restart arm's `reopened`, `session` and `refused` among them
/// — a declared optional member of `DeathReason`, every declared member
/// built by some arm, so a rename or a removal in the code alone, or in the
/// table alone, fails here. And the `session` answer's `opened_at` is
/// declared optional, a number.
#[test]
fn the_deaths_members_and_the_sessions_open_position_are_declared() {
    let event = shape("SessionDiedEvent").unwrap();
    assert_eq!(event.fields.iter().map(|f| (f.name, f.required)).collect::<Vec<_>>(), [("session", true), ("reason", true)]);
    let reason = shape("DeathReason").unwrap();
    assert_eq!(reason.fields.iter().filter(|f| f.required).map(|f| f.name).collect::<Vec<_>>(), ["arm"], "the arm alone is required");
    let declared: BTreeSet<&str> = reason.fields.iter().filter(|f| !f.required).map(|f| f.name).collect();
    let fp = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    let arms = [
        sessions::closed(),
        sessions::unreachable_reason("connect: refused"),
        sessions::mode_reason(skep_client::derive::Mode::Enforcing),
        sessions::restart_reason(None, None),
        sessions::restart_reason(Some("s-1"), None),
        sessions::restart_reason(None, Some("busy")),
        sessions::retired_reason(&fp, None, None),
        sessions::seeded_reason("1.0.1.1", 9, Some("ab")),
        sessions::blocked_reason("1.0.1.0.7.1", None),
    ];
    let mut built: BTreeSet<String> = BTreeSet::new();
    for arm in &arms {
        assert_declared("DeathReason", arm);
        built.extend(keys(arm).into_iter().filter(|member| member != "arm"));
    }
    let built: BTreeSet<&str> = built.iter().map(String::as_str).collect();
    assert_eq!(built, declared, "every member an arm is built with is declared, and none is declared that no arm builds");
    for member in ["reopened", "session", "refused"] {
        assert!(declared.contains(member), "the restart arm's `{member}` is declared");
    }
    let reopened = sessions::restart_reason(Some("s-1"), None);
    assert_eq!((reopened["reopened"].as_bool(), reopened["session"].as_str(), reopened.get("refused")), (Some(true), Some("s-1"), None), "{reopened}");
    let refused = sessions::restart_reason(None, Some("busy"));
    assert_eq!((refused["reopened"].as_bool(), refused.get("session"), refused["refused"].as_str()), (Some(false), None, Some("busy")), "{refused}");
    let opened_at = shape("SessionOpened").unwrap().fields.iter().find(|f| f.name == "opened_at").expect("`opened_at` is declared");
    assert_eq!((opened_at.required, opened_at.ty), (false, "number"));
}

/// The board's `site` crosses with every member the wire names (skep #713).
///
/// A verdict whose `site` carries the wire's eight — `addr`, `index`,
/// `operand`, `region`, `slot`, `fault`, and an `arrangement_moved`'s
/// `as_of` and `current` — reaches the page's value with each, typed as the
/// board fills it and as the declaration spells it; a member the board
/// fills in another type, or the page could not read, crosses not at all
/// (the mutant that copies `addr` and `index` alone leaves the page reading
/// untyped members off the body, which the contract never promised).
#[test]
fn the_boards_site_crosses_with_every_member_the_wire_names() {
    let site = json!({"addr": "1.0.1.0.1", "index": 2, "operand": "first", "region": 1, "slot": 3, "fault": "not_ordinal_level", "as_of": 7, "current": 9, "other": true, "region_text": "x"});
    let body = json!({"resp": "rejected", "code": "arrangement_moved", "disposition": "permanent", "op": "insert", "site": site});
    let refused = Refusal::Board(Refused { status: 200, code: "arrangement_moved".into(), detail: None, op: Some("insert".into()), body }).to_value();
    assert_eq!(refused["site"], json!({"addr": "1.0.1.0.1", "index": 2, "operand": "first", "region": 1, "slot": 3, "fault": "not_ordinal_level", "as_of": 7, "current": 9}), "{refused}");
    let declared = shape("RefusedByBoard").unwrap().fields.iter().find(|f| f.name == "site").unwrap().ty;
    for member in ["addr?: string", "index?: number", "operand?: 'first' | 'second'", "region?: number", "slot?: number", "fault?: string", "as_of?: number", "current?: number"] {
        assert!(declared.contains(member), "the declaration spells `{member}`: {declared}");
    }
    let mistyped = Refusal::Board(Refused { status: 200, code: "x".into(), detail: None, op: None, body: json!({"site": {"addr": 7, "index": "2", "as_of": "7"}}) }).to_value();
    assert_eq!(mistyped["site"], json!({}), "a member of another type crosses not at all: {mistyped}");
}
