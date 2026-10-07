use super::*;
use crate::outcome::Disagreement;

fn key(s: &str) -> ScenarioKey {
    s.parse().expect("a scenario key")
}

fn outcome(index: usize, status: Status, expected: Option<&str>) -> OpOutcome {
    let mut o = OpOutcome::new(index, "probe");
    o.status = status;
    o.disagreement =
        expected.map(|e| Disagreement { expected: e.to_string(), actual: "got".into() });
    o
}

/// An entry over `op_index` (every op when `None`) of `cat/s`.
fn entry(
    op_index: Option<usize>,
    class: &str,
    count_delta: Option<i64>,
    width_tolerance: Option<u64>,
    expected_matches: Option<&str>,
) -> Entry {
    Entry {
        line: 0,
        scenario: key("cat/s"),
        op_index,
        class: class.into(),
        count_delta,
        width_tolerance,
        expected_matches: expected_matches.map(str::to_string),
    }
}

/// A disagreement is covered by the entries matching its op and the
/// signature entries its expected value matches — a signature entry's op
/// index restricting it too. An agreement is covered only by the entries
/// whose declared adjustment a comparator recorded making it: a width
/// tolerance by the entries declaring one, a count delta by the entry
/// declaring it — none when no entry over the op declares the adjustment.
/// A signature entry adjusts nothing, whatever it declares.
#[test]
fn an_entry_classifies_disagreements_and_only_the_agreements_its_adjustment_made() {
    let s = key("cat/s");
    let signature = |op_index, class| entry(op_index, class, Some(2), Some(5), Some("(\"0\""));
    let allow = Allowlist {
        entries: vec![
            entry(Some(1), "tolerated", None, Some(1), None),
            entry(Some(1), "counted", Some(1), None, None),
            entry(Some(3), "widened", None, Some(2), None),
            signature(None, "shape"),
            signature(Some(5), "elsewhere"),
        ],
    };
    assert_eq!(allow.adjustments(&s, 1), Adjustments { width_tolerance: 1, count_delta: 1 });
    assert_eq!(allow.adjustments(&s, 2), Adjustments::default());

    let adjusted = |index: usize, tags: &[&str]| {
        let mut o = outcome(index, Status::Agreed, None);
        o.adaptations.extend(tags.iter().map(|t| t.to_string()));
        allow.classify(&s, index, &o)
    };
    assert_eq!(adjusted(1, &[]), None, "no adjustment made this agreement");
    assert_eq!(adjusted(1, &[WIDTH_ADJUSTED]).as_deref(), Some("tolerated"));
    assert_eq!(adjusted(1, &[COUNT_ADJUSTED]).as_deref(), Some("counted"));
    let both = adjusted(1, &[WIDTH_ADJUSTED, COUNT_ADJUSTED]);
    assert_eq!(both.as_deref(), Some("tolerated+counted"));
    assert_eq!(adjusted(3, &[COUNT_ADJUSTED]), None, "no entry over op 3 declares a delta");

    let shaped = outcome(2, Status::Disagreed, Some("[(\"0\", \"0.1\")]"));
    assert_eq!(allow.classify(&s, 2, &shaped).as_deref(), Some("shape"));
    let other = outcome(2, Status::Disagreed, Some("[(\"1.1\", \"0.3\")]"));
    assert_eq!(allow.classify(&s, 2, &other), None);
    let both = outcome(1, Status::Disagreed, Some("(\"0\""));
    assert_eq!(allow.classify(&s, 1, &both).as_deref(), Some("tolerated+counted+shape"));
    assert_eq!(allow.classify(&key("cat/t"), 1, &both), None, "entries are per scenario");
}

/// An entry rules on golden ops: one whose key no loaded golden carries, or
/// whose op index lies past its scenario's ops, is unanchored, named by the
/// line its block opens at; one within them is not.
#[test]
fn an_entry_ruling_on_no_golden_op_is_unanchored() {
    let dir = std::env::temp_dir().join(format!("skep-allowlist-anchor-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a scratch directory");
    let block = |scenario: &str, op: &str| {
        let ruling = "class = \"c\"\nrationale = \"r\"\n";
        format!("[[allow]]\nscenario = \"{scenario}\"\n{op}{ruling}")
    };
    let path = dir.join("allowlist.toml");
    let text =
        [block("cat/s", "op_index = 2\n"), block("cat/gone", ""), block("cat/s", "op_index = 3\n")];
    fs::write(&path, text.concat()).expect("an allowlist");
    let allow = load(&path);
    fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    let unanchored = allow.expect("the allowlist loads").unanchored(&[(key("cat/s"), 3)]);
    assert_eq!(
        unanchored,
        [
            "allowlist line 6: `cat/gone` — no golden scenario carries the key",
            "allowlist line 10: `cat/s` op_index 3 — the scenario has 3 ops",
        ]
    );
}

/// Two entries over one op declaring different count deltas are refused,
/// at the later entry — file order never settles which delta applies; one
/// delta declared twice, deltas over different ops, and a signature
/// entry's delta, which never applies, are no conflict.
#[test]
fn two_entries_over_one_op_declaring_different_deltas_are_refused() {
    let conflict = |entries: Vec<Entry>| {
        let lined: Vec<Entry> =
            entries.into_iter().enumerate().map(|(k, e)| Entry { line: k + 1, ..e }).collect();
        conflicting_delta(&lined)
    };
    let delta = |op_index, d| entry(op_index, "c", Some(d), None, None);
    assert_eq!(conflict(vec![delta(None, 1), delta(Some(4), 2)]), Some(2));
    assert_eq!(conflict(vec![delta(Some(4), 1), delta(Some(4), 2)]), Some(2));
    assert_eq!(conflict(vec![delta(Some(4), 1), delta(None, 1)]), None);
    assert_eq!(conflict(vec![delta(Some(4), 1), delta(Some(5), 2)]), None);
    let signature = entry(Some(4), "c", Some(2), None, Some("x"));
    assert_eq!(conflict(vec![delta(Some(4), 1), signature]), None);
}

/// An entry names its scenario by key: a bare name — which two goldens
/// can share — is refused on the line that wrote it, never left to match
/// nothing; and an entry without its class or rationale is incomplete.
#[test]
fn an_entry_names_its_scenario_by_key() {
    let dir = std::env::temp_dir().join(format!("skep-allowlist-keys-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a scratch directory");
    let entry = |scenario: &str| {
        format!("[[allow]]\nscenario = \"{scenario}\"\nclass = \"c\"\nrationale = \"r\"\n")
    };
    let path = dir.join("allowlist.toml");
    fs::write(&path, entry("discovery/find_documents_basic")).expect("an allowlist");
    let keyed = load(&path).map(|a| a.entries[0].scenario.clone());
    fs::write(&path, entry("find_documents_basic")).expect("an allowlist");
    let bare = load(&path).err();
    fs::write(&path, "[[allow]]\nscenario = \"cat/s\"\nclass = \"c\"\n").expect("an allowlist");
    let unruled = load(&path).err();
    fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    assert_eq!(keyed.ok(), Some(key("discovery/find_documents_basic")));
    assert!(matches!(bare, Some(AllowlistError::NotAKey { line: 2, .. })), "{bare:?}");
    assert!(matches!(unruled, Some(AllowlistError::Incomplete { .. })), "{unruled:?}");
}

/// A missing allowlist is the empty one; an allowlist that is there and
/// cannot be read is an error, never read as empty.
#[test]
fn only_a_missing_allowlist_loads_empty() {
    let dir = std::env::temp_dir().join(format!("skep-allowlist-read-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a scratch directory");
    let missing = load(&dir.join("absent.toml")).map(|a| a.entries.len());
    let unreadable = load(&dir).err();
    fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    assert_eq!(missing.ok(), Some(0));
    assert!(matches!(unreadable, Some(AllowlistError::Read { .. })), "{unreadable:?}");
}

/// The format refuses what it does not speak, each refusal at its line:
/// an unknown key — a misspelled adjustment would otherwise widen a
/// comparator unseen — a key outside a block, an unquoted string, a key
/// set twice in one block, whose second value would move the ruling,
/// and an empty signature, which every expected value contains; an
/// empty class leaves its entry incomplete.
#[test]
fn a_line_outside_the_format_is_refused() {
    let scratch = format!("skep-allowlist-format-{}", std::process::id());
    let dir = std::env::temp_dir().join(scratch);
    fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("allowlist.toml");
    let refusal = |text: &str| {
        fs::write(&path, text).expect("an allowlist");
        load(&path).err()
    };
    let entry = "[[allow]]\nscenario = \"cat/s\"\nclass = \"c\"\nrationale = \"r\"\n";
    let misspelled = refusal(&format!("{entry}widht_tolerance = 1\n"));
    let outside = refusal("class = \"c\"\n");
    let unquoted = refusal("[[allow]]\nscenario = cat/s\n");
    let unclassed = refusal("[[allow]]\nscenario = \"cat/s\"\nclass = \"\"\nrationale = \"r\"");
    let moved = refusal(&format!("{entry}op_index = 2\nop_index = 7\n"));
    let unsigned = refusal(&format!("{entry}expected_matches = \"\"\n"));
    fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    let syntax_at = |line: usize, key: &'static str| {
        move |e: &AllowlistError| match e {
            AllowlistError::Syntax { line: l, problem } => *l == line && problem.contains(key),
            _ => false,
        }
    };
    assert!(misspelled.as_ref().is_some_and(syntax_at(5, "widht_tolerance")), "{misspelled:?}");
    assert!(matches!(outside, Some(AllowlistError::Syntax { line: 1, .. })), "{outside:?}");
    assert!(matches!(unquoted, Some(AllowlistError::Syntax { line: 2, .. })), "{unquoted:?}");
    assert!(matches!(unclassed, Some(AllowlistError::Incomplete { .. })), "{unclassed:?}");
    assert!(moved.as_ref().is_some_and(syntax_at(6, "op_index")), "{moved:?}");
    assert!(unsigned.as_ref().is_some_and(syntax_at(5, "expected_matches")), "{unsigned:?}");
}
