//! THE PIN (F8): a sample of every declared type, built as the crate's code
//! builds it, round-tripped through `serde_json` and its field names held
//! equal to the table's — every required field present, no field outside
//! the table — so a field renamed in the declaration alone, or in the code
//! alone, fails here; and the file names every shape, every call and every
//! event.

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
/// the death through `sessions`, the rest in the shape `shell`'s and
/// `shell::publication`'s `json!` spell (the publication family's answers
/// are held to their declarations against the real board by the shell's
/// own suite, `shell/tests/publication.rs`).
fn samples() -> Vec<(&'static str, Value)> {
    let facts = json!({"principal": 1, "account": "1.0.1", "origin": "http://127.0.0.1:8642"});
    vec![
        ("BoardRow", json!({"board": "b-0", "name": "http://127.0.0.1:8642", "origin": "http://127.0.0.1:8642"})),
        ("SessionOpened", json!({"session": "s-0", "principal": 1, "account": "1.0.1", "writes": true})),
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
        ("HaltFace", Refusal::named(Name::NO_KEY, Face { state: "s".into(), cause: "c".into(), act: "a".into() }).to_value()),
        ("BlockedFace", Refusal::Blocked(Blocked { record: "1.0.1.0.7.1".into(), named_by: "http://x".into(), ground: None }).to_value()),
        ("Unreachable", Refusal::Unreachable(DialError::Connect("refused".into())).to_value()),
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
        ("HeldAnswer", json!({"resp": "held", "held": 1, "cause": "unreachable"})),
        ("HeldRow", json!({"held": 1, "doc": "1.0.1.0.1", "base": 5, "frame": {"op": "insert"}, "cause": "unreachable", "sent": false, "time": 1})),
        ("HeldEvent", json!({"board": "b-0", "session": "s-0", "doc": "1.0.1.0.1", "held": 2, "state": "moved", "hands": [{"key": "bare"}]})),
        ("Hand", json!({"key": "other", "fingerprint": "ab", "label": "phone"})),
        ("Resolve", json!({"session": "s-0", "held": 1, "act": "drop"})),
        ("Run", json!({"origin": "1.0.1.0.5", "i_start": 1, "width": 10})),
        (
            "PublicationPanel",
            json!({"rows": [], "formatting": {"marks": [], "cut": 0, "removals": []}, "read_with": {"1.0.1.0.3": true}, "count": {"l": 0, "n": 0, "r": 0, "e": 0, "claim": false, "read_with": []}, "price": {"lists": [0, 0, 0, 0, 0], "body": 0, "values": 0, "reads": 0, "bytes": 0, "over": []}, "windows": [], "hold": {"since": 1}}),
        ),
        ("PublicationRow", json!({"home": "1.0.1.0.5", "kind": {"public": {"read_with": false}}, "label": "notes here", "links": ["1.0.1.0.5.0.2.1"], "types": [], "line": {"p": 0, "d": 0, "c": 0, "t": 0, "u": 0}, "read_through": 0})),
        ("TypeFold", json!({"ty": "1.1.0.1.0.1.0.3.13", "n": 1, "far": ["1.0.1.0.8"]})),
        ("RowLine", json!({"p": 1, "d": 0, "c": 0, "t": 0, "u": 0})),
        ("Formatting", json!({"marks": ["1.0.1.0.5.0.2.1"], "cut": 1, "removals": []})),
        ("Removal", json!({"record": "1.0.1.0.5.0.2.9", "mark": "1.0.1.0.2.1.0.2.1", "mark_value": {"from": [], "to": [], "ty": [], "at": 7}, "on_selection": true, "spent": false, "remake": null})),
        ("LinkValue", json!({"from": [{"start": "1.0.1.0.2.0.1.5", "width": "0.0.0.0.0.0.0.5"}], "to": [], "ty": [{"start": "1.1.0.1.0.1.0.3.13", "width": "0.0.0.0.0.0.0.0.1"}], "at": 7})),
        ("LinkSpan", json!({"start": "1.0.1.0.2.0.1.5", "width": "0.0.0.0.0.0.0.5"})),
        ("Count", json!({"l": 3, "n": 2, "r": 1, "e": 0, "claim": false, "read_with": ["1.0.1.0.4"]})),
        ("Price", json!({"lists": [3, 1, 4, 1, 1], "body": 120, "values": 10, "reads": 20, "bytes": 5000, "over": [{"term": "lists", "by": 1}]})),
        ("PriceOver", json!({"term": "links", "by": 4})),
        ("Window", json!({"run": 2, "origin": "1.0.1.0.7", "owner": "1.0.1", "i_start": 1, "width": 5, "counterpart": {"run": 2, "draft": "1.0.1.0.7", "record": "1.0.1.0.7.0.2.1", "from": {"chain": "1.0.1.0.7.0.1", "first": 1, "width": 4}, "to": {"chain": "1.0.1.0.2.0.1", "first": 16, "width": 4}}})),
        ("Counterpart", json!({"run": 2, "draft": "1.0.1.0.7", "record": "1.0.1.0.7.0.2.1", "from": {"chain": "1.0.1.0.7.0.1", "first": 1, "width": 4}, "to": {"chain": "1.0.1.0.2.0.1", "first": 16, "width": 4}})),
        ("ISpan", json!({"chain": "1.0.1.0.7.0.1", "first": 1, "width": 4})),
        ("Hold", json!({"since": 1_761_696_000_000u64})),
        ("Switches", json!({"on": ["1.0.1.0.6"], "destinations": {"1.0.1.0.6": {"set": "1.0.1.0.4"}}})),
        ("Acknowledged", json!({"outcome": "acknowledged", "member": "1.0.1.0.2.2", "edition": null, "claim": false, "at": 412, "via": "answer"})),
        ("Restated", json!({"outcome": "restated", "left": [], "superseded": [], "came": ["1.0.1.0.6.0.2.3"], "removals_undone": [], "removals_came": [], "selection": [{"run": 1, "placement": {"split": [[1, 2, 1], [3, 3, 1]]}}], "race": {"at": 999, "key": "bare", "signed": false}})),
        ("RaceKey", json!({"at": 999, "key": "bare", "signed": false})),
        ("PublicationRefused", json!({"outcome": "refused", "arm": "claim_refused", "edition": "1.0.1.0.2"})),
        ("PublicationEvent", json!({"board": "b-0", "session": "s-0", "draft": "1.0.1.0.5", "state": "acknowledged", "member": "1.0.1.0.2.2", "edition": null, "at": 412})),
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
/// — both answers and the seven events; a field's optionality renders as
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
    assert_eq!(CALL_ROWS.len(), 28, "the twenty-eight calls: §4b.1's with the publication family's four, the document index's listing and the change feed's page");
    assert_eq!(CALL_ROWS.iter().map(|row| row.name).collect::<Vec<_>>(), crate::CALLS, "the declared rows are the dispatch's calls, in its order");
    for line in [
        "  boards(args: {}): Promise<Outcome<BoardRow[]>>;\n",
        "  session(args: { board: string; principal?: number }): Promise<Outcome<SessionOpened>>;\n",
        "  op(args: { session: string; frame: unknown } | { guest: true; board?: string; origin?: string; frame: unknown }): Promise<Outcome<unknown>>;\n",
        "  'publication.open'(args: { session: string; draft: string; doc?: string; mint?: string; claim?: boolean; selection?: Run[]; notes?: string[]; readable_drafts?: string[]; published?: string[] }): Promise<Outcome<PublicationPanel>>;\n",
        "  'publication.count'(args: { session: string; switches?: Switches; answers?: Record<string, OriginAnswer> }): Promise<Outcome<{ count: Count; price: Price }>>;\n",
        "  'publication.confirm'(args: { session: string; switches?: Switches; answers?: Record<string, OriginAnswer> }): Promise<Outcome<Acknowledged | Restated | PublicationRefused>>;\n",
        "  'publication.cancel'(args: { session: string }): Promise<Outcome<Empty>>;\n",
        "  places(args: { session: string; board?: string; opts?: PlacesOpts } | { guest: true; board?: string; origin?: string; opts?: PlacesOpts }): Promise<Outcome<PlacesAnswer>>;\n",
        "  changes(args: { session: string; since: number; limit?: number }): Promise<Outcome<ChangesAnswer>>;\n",
        "export interface PlacesOpts { under?: string }\n",
        "export type OriginAnswer = 'publish_first' | 'drop' | 'keep_private' | 'counterpart';\n",
        "export type RowKind = 'own' | 'notes' | 'private' | { public: { read_with: boolean } };\n",
        "  writes: boolean;\n",
        "  entries: FeedUpdate[];\n",
        "  hands?: Hand[];\n",
        "  site: { addr?: string; index?: number };\n",
    ] {
        assert!(text.contains(line), "the row renders as declared: {line}");
    }
    for alias in ALIASES {
        assert!(text.contains(&format!("{alias}\n")), "the alias renders ahead of the shapes: {alias}");
    }
    assert!(text.contains("  answer(args: Answer)") && text.contains("  cancel(args: Cancel)"));
    assert!(
        text.contains("export type EventName = 'mode' | 'session-died' | 'daemon' | 'feed' | 'index' | 'moment' | 'held' | 'publication';\n\n"),
        "the eight event names render from the enum, in the contract's order"
    );
    assert!(text.contains("  warning?: string;"), "an optional field renders with `?`");
    assert!(text.contains("  position: number;"), "a required field renders bare");
    let open = SHAPES.iter().filter(|s| s.open).count();
    assert_eq!(open, 5, "the shell refusal, the death's reason, the index state, the publication's refusal and its event carry their own members");
    assert_eq!(text.matches("  [member: string]: unknown;\n").count(), open, "an open shape, and it alone, renders its index signature");
    assert!(text.starts_with("// skep-shell — the bridge's declarations"));
}
