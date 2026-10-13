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
use crate::feed::{answer_without_index, state_json};
use crate::refusal::{Name, Refusal};
use crate::sessions;

/// One sample per declared type: the value the crate's code answers or
/// emits for it — the refusals through `Refusal::to_value`, the search
/// answer through `feed::answer_without_index`, the index state through
/// `feed::state_json`, the death through `sessions`, the rest in the shape
/// `shell`'s `json!` spells.
fn samples() -> Vec<(&'static str, Value)> {
    let facts = json!({"principal": 1, "account": "1.0.1", "origin": "http://127.0.0.1:8642"});
    vec![
        ("BoardRow", json!({"board": "b-0", "name": "http://127.0.0.1:8642", "origin": "http://127.0.0.1:8642"})),
        ("SessionOpened", json!({"session": "s-0", "principal": 1, "account": "1.0.1"})),
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
        ("HeldEvent", json!({"board": "b-0", "session": "s-0", "doc": "1.0.1.0.1", "held": 2, "state": "holding", "cause": "unreachable"})),
        ("Resolve", json!({"session": "s-0", "held": 1, "act": "drop"})),
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

/// The file names every shape, every call of §4b.1 — its rows the
/// dispatch's calls, in the dispatch's order — both answers and the seven
/// events; a field's optionality renders as `?`.
#[test]
fn the_file_names_every_shape_call_and_event() {
    let text = declarations();
    for shape in SHAPES {
        assert!(text.contains(&format!("export interface {} {{", shape.name)), "{}", shape.name);
    }
    for (name, _, _) in CALLS {
        assert!(text.contains(&format!("  {name}(args: ")), "{name}");
    }
    assert_eq!(CALLS.len(), 22, "the twenty-two calls");
    assert_eq!(CALLS.iter().map(|c| c.0).collect::<Vec<_>>(), crate::CALLS, "the declared rows are the dispatch's calls, in its order");
    assert!(text.contains("  answer(args: Answer)") && text.contains("  cancel(args: Cancel)"));
    assert!(
        text.contains("export type EventName = 'mode' | 'session-died' | 'daemon' | 'feed' | 'index' | 'moment' | 'held';\n\n"),
        "the seven event names render from the enum, in the contract's order"
    );
    assert!(text.contains("  warning?: string;"), "an optional field renders with `?`");
    assert!(text.contains("  position: number;"), "a required field renders bare");
    let open = SHAPES.iter().filter(|s| s.open).count();
    assert_eq!(open, 3, "the shell refusal, the death's reason and the index state carry their own members");
    assert_eq!(text.matches("  [member: string]: unknown;\n").count(), open, "an open shape, and it alone, renders its index signature");
    assert!(text.starts_with("// skep-shell — the bridge's declarations"));
}
