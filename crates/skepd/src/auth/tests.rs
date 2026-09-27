use super::*;

/// AUTH-4.2 — the canonical-member rule: at the scheme's default port
/// the port is omitted, and `parse` admits only the canonical text.
#[test]
fn origins_are_canonical_only() {
    for ok in ["http://127.0.0.1:8642", "http://localhost:8642", "http://[::1]:8642",
               "http://127.0.0.1", "https://example.org", "https://skep.example:8443"] {
        let o = Origin::parse(ok).unwrap_or_else(|| panic!("'{ok}' is canonical"));
        assert_eq!(o.as_str(), ok);
    }
    for bad in ["http://127.0.0.1:80", "https://example.org:443", "HTTP://x",
                "http://X.org", "http://x/", "http://x/path", "null", "",
                "http://x:08642", "ftp://x", "http://", "http://x:", "http://x:0"] {
        assert!(Origin::parse(bad).is_none(), "'{bad}' must not parse");
    }
}

/// AUTH-4.1 — the defaults are the three loopback origins of the bound
/// port, canonical (port omitted at 80) — and an UNBOUND config has
/// none, which is the honest degenerate stated in the type: the
/// alternative is three members at a port no listener serves and no
/// `Origin` header can name.
#[test]
fn loopback_defaults_are_the_three_canonical_members() {
    let at_8642: Vec<String> =
        loopback_defaults(Some(8642)).iter().map(|o| o.as_str().to_string()).collect();
    assert_eq!(
        at_8642,
        ["http://127.0.0.1:8642", "http://[::1]:8642", "http://localhost:8642"]
    );
    let at_80: Vec<String> =
        loopback_defaults(Some(80)).iter().map(|o| o.as_str().to_string()).collect();
    assert_eq!(at_80, ["http://127.0.0.1", "http://[::1]", "http://localhost"]);
    assert!(loopback_defaults(None).is_empty(), "an unbound config derives no defaults");
}

/// [`AuthConfig::bind_port`] refuses a second bind and names the port
/// already bound — the number every live session's origin set was
/// established against, which is what the second caller needs told.
#[test]
fn a_second_bind_is_refused_and_names_the_bound_port() {
    let cfg = cfg_with(8642, true, &[]);
    assert_eq!(cfg.port(), Some(8642));
    assert_eq!(
        cfg.bind_port(9999),
        Err(PortAlreadyBound(8642)),
        "the bound port, not the refused one"
    );
    assert_eq!(cfg.port(), Some(8642), "and the binding did not move");
}

/// Port 0 is the one value from which [`loopback_defaults`] derives
/// origins [`Origin::parse`] refuses: `http://127.0.0.1:0` fails the
/// leading-zero clause, so admitting the bind fires
/// [`Origin::from_parts`]'s debug assert on every request that reads a
/// derived origin, and in release publishes a `/health` set whose
/// members no `Origin` header can match. The bind refuses it instead —
/// a caller's bug, stopped loudly, as a zero worker count is at
/// [`crate::serve`].
#[test]
#[should_panic(expected = "port 0 is not a port")]
fn port_zero_is_a_callers_bug() {
    // The premise, first: this is what the defaults would derive from it.
    assert!(
        Origin::parse("http://127.0.0.1:0").is_none(),
        "the front door refuses the text a zero-port default would carry"
    );
    let cfg = AuthConfig::new(AuthOptions::default());
    let _ = cfg.bind_port(0);
}

/// An unbound config has no port, so its bare set is `configured`
/// alone — no unmatchable members, and nothing `/health` publishes that
/// [`Origin::parse`] would refuse if an operator copied it back.
#[test]
fn an_unbound_config_derives_no_origins() {
    let cfg = AuthConfig::new(AuthOptions {
        local_trust: true,
        configured: vec![Origin::parse("https://board.example").expect("canonical")],
        ..AuthOptions::default()
    });
    assert_eq!(cfg.port(), None);
    let bare = bare_origins(&cfg);
    assert_eq!(bare.len(), 1, "configured alone: {bare:?}");
    assert!(bare.contains(&Origin::parse("https://board.example").unwrap()));
}

fn cfg_with(port: u16, local_trust: bool, configured: &[&str]) -> AuthConfig {
    let cfg = AuthConfig::new(AuthOptions {
        local_trust,
        configured: configured.iter().map(|s| Origin::parse(s).expect("canonical")).collect(),
        ..AuthOptions::default()
    });
    cfg.bind_port(port).expect("a fresh config binds once");
    cfg
}

/// AUTH-4.3 — the two sets: bare keeps the defaults in every mode;
/// signed drops to configured alone at the claim.
#[test]
fn the_two_origin_sets_split_at_the_claim() {
    let cfg = cfg_with(8642, false, &["https://board.example"]);
    let bare = bare_origins(&cfg);
    assert_eq!(bare.len(), 4, "configured ∪ the three defaults");
    assert!(bare.contains(&Origin::parse("http://localhost:8642").unwrap()));
    let unclaimed = signed_origins(&cfg, false);
    assert_eq!(unclaimed, bare, "unclaimed: the signed set is the bare set");
    let claimed = signed_origins(&cfg, true);
    assert_eq!(claimed.len(), 1, "claimed: configured alone");
    assert!(claimed.contains(&Origin::parse("https://board.example").unwrap()));
}

/// AUTH-4.9/AUTH-4.62 item 9 — the warning cells, the canonical-form
/// cell included: bound at 80, configured `http://127.0.0.1` is silent
/// and `http://127.0.0.1:8080` warns, naming the origin.
#[test]
fn each_warning_arm_fires_only_on_its_own_cell() {
    assert!(startup_warnings(&cfg_with(8642, false, &["https://b.example"]), true).is_empty());
    assert_eq!(
        startup_warnings(&cfg_with(8642, true, &["https://b.example"]), true),
        [Warning::ClaimedWithLocalTrust]
    );
    assert_eq!(
        startup_warnings(&cfg_with(8642, false, &[]), true),
        [Warning::ClaimedWithEmptyConfigured]
    );
    let moved = cfg_with(80, false, &["http://127.0.0.1", "http://127.0.0.1:8080"]);
    assert_eq!(
        startup_warnings(&moved, false),
        [Warning::ConfiguredLoopbackPortChanged(
            Origin::parse("http://127.0.0.1:8080").unwrap()
        )],
        "the canonical member is silent; the moved port warns and is named"
    );
    // A hosted board configured with its public origin alone is silent.
    assert!(startup_warnings(&cfg_with(443, false, &["https://b.example"]), false).is_empty());
}

fn addr(s: &str) -> Address {
    wire_address(s).expect("a T4-valid address")
}

fn node_prefix(s: &str) -> NodePrefix {
    s.parse().expect("a node prefix")
}

fn issue(operator: Option<&str>, binding_writer: Option<&str>, entries: &[(&str, &str)]) -> BlockedIssue {
    BlockedIssue {
        header: BlockedHeader {
            operator: operator.map(addr),
            binding_writer: binding_writer.map(addr),
        },
        entries: entries
            .iter()
            .map(|(prefix, record)| BlockedEntry { prefix: addr(prefix), record: addr(record) })
            .collect(),
    }
}

/// AUTH-4.36 step 4b's predicate: M3's containment, the LONGEST covering
/// prefix's record, COVER and never descent (AUTH-4.70) — an entry over
/// `X.k` covers `X.k` and everything below it and does not reach `X` —
/// and component-wise, so `1.0.2` does not contain `1.0.21`.
#[test]
fn covers_answers_the_longest_covering_entrys_record() {
    let list = BlockedPrefixes::installed_under(
        issue(None, None, &[("1.0.2", "1.0.1.0.7.1"), ("1.0.2.1", "1.0.1.0.8.1")]),
        None,
        None,
    );
    assert_eq!(list.covers(&addr("1.0.2")), Some(&addr("1.0.1.0.7.1")), "the prefix itself");
    assert_eq!(list.covers(&addr("1.0.2.5")), Some(&addr("1.0.1.0.7.1")), "and below it");
    assert_eq!(list.covers(&addr("1.0.2.1")), Some(&addr("1.0.1.0.8.1")), "the longest");
    assert_eq!(list.covers(&addr("1.0.2.1.4")), Some(&addr("1.0.1.0.8.1")));
    assert_eq!(list.covers(&addr("1.0.3")), None, "a sibling");
    assert_eq!(list.covers(&addr("1.0.21")), None, "containment is by component");
    let below =
        BlockedPrefixes::installed_under(issue(None, None, &[("1.0.2.1", "1.0.1.0.8.1")]), None, None);
    assert_eq!(below.covers(&addr("1.0.2")), None, "an entry over X.k does not reach X");
    // Two entries over ONE prefix: the first in supply order answers.
    let tied = BlockedPrefixes::installed_under(
        issue(None, None, &[("1.0.2", "1.0.1.0.7.1"), ("1.0.2", "1.0.1.0.8.1")]),
        None,
        None,
    );
    assert_eq!(tied.covers(&addr("1.0.2")), Some(&addr("1.0.1.0.7.1")));
    assert_eq!(BlockedPrefixes::default().covers(&addr("1.0.2")), None, "no supply, no block");
}

/// THE INSTALL'S TWO INERT COMPARANDS, at every cell AUTH-4.36 step 4b
/// states: (a) and (b) one account where the header names none; (b)
/// SILENT on a fork the community itself serves; (b) LIVE where the host
/// is off-board — the claimant taken where the header omits the second
/// field, the SEAT and never the old claimant where it names one. Every
/// board here is launched `--node-prefix 1.3`, so the off-board test is
/// LIVE and reads the header's operator against that prefix (REG-1.69):
/// the seat a self-served fork names is spelled in the GLOBAL form the
/// header carries, `1.3.0.2`, and so is the entry over it — the operator
/// is read as spelled against the entries too, and a LOCAL-form entry
/// over the same account stands (the last cell; the report escalates the
/// form).
#[test]
fn the_install_ignores_exactly_the_entries_covering_a_comparand() {
    let (claimant, seat, member, host) = ("1.0.1", "1.0.2", "1.0.3", "2.0.7");
    let seat_global = "1.3.0.2";
    let record = "1.0.1.0.7.1";
    let prefix = node_prefix("1.3");
    let entries =
        [(claimant, record), (seat, record), (member, record), (host, record), (seat_global, record)];
    let verdicts = |operator, binding_writer, claimed: Option<&str>| {
        let claimed = claimed.map(addr);
        BlockedPrefixes::installed_under(
            issue(operator, binding_writer, &entries),
            claimed.as_ref(),
            Some(&prefix),
        )
        .inert
    };
    let (a, b) = (Some(Comparand::Operator), Some(Comparand::BindingWriter));
    assert_eq!(
        verdicts(None, None, Some(claimant)),
        [a, None, None, None, None],
        "the root: the header names none, so the claimant is the one comparand"
    );
    assert_eq!(
        verdicts(Some(seat_global), None, Some(claimant)),
        [None, None, None, None, a],
        "a self-served fork: the seat is on-board (under the prefix), (b) is silent, the \
         old claimant blockable — and the operator is read as spelled: the global-form \
         entry over the seat is inert, the local-form one stands"
    );
    assert_eq!(
        verdicts(Some(host), None, Some(claimant)),
        [b, None, None, a, None],
        "a hosted tier: the operator off-board, the claimant taken for the omitted field"
    );
    assert_eq!(
        verdicts(Some(host), Some(seat), Some(claimant)),
        [None, b, None, a, None],
        "a third-party-hosted fork: the SEAT exempt, never the old claimant"
    );
    assert_eq!(
        verdicts(None, None, None),
        [None, None, None, None, None],
        "unclaimed, the header naming none: no comparand, every entry stands as issued"
    );
    assert_eq!(
        verdicts(Some(seat), None, Some(claimant)),
        [b, a, None, None, None],
        "the seat spelled in the LOCAL form is under no `1.N` and reads OFF-board: (b) \
         goes live and exempts the old claimant — the header's first field is the \
         operator's to spell globally (escalated)"
    );
    // COVER: a prefix ABOVE a comparand covers it — the board's own node
    // included — and one BELOW it does not.
    let list = BlockedPrefixes::installed_under(
        issue(None, None, &[("1", record), ("1.0.1.1", record)]),
        Some(&addr(claimant)),
        Some(&prefix),
    );
    assert_eq!(list.inert, [a, None], "above is inert; the agent space beneath blocks");
    assert_eq!(list.covers(&addr(member)), None, "an inert entry blocks nobody");
    assert!(list.covers(&addr("1.0.1.1")).is_some());
}

/// The claim flip's log question ([`BlockedPrefixes::issue_is_empty`]) is
/// about the ISSUE and never about the entries in force. The two differ
/// at exactly the cell the flip's log exists for — every entry inert,
/// because the claimant the flip seats is what made them so — so a
/// version asking `in_force() == 0` instead would fall silent on the one
/// install AUTH-4.36 step 4b requires be "said so in the log".
#[test]
fn an_all_inert_issue_is_not_an_empty_one() {
    let claimant = addr("1.0.1");
    let all_inert = BlockedPrefixes::installed_under(
        issue(None, None, &[("1.0.1", "1.0.1.0.9.1")]),
        Some(&claimant),
        Some(&node_prefix("1.3")),
    );
    assert_eq!(all_inert.in_force(), 0, "the claim made its one entry inert");
    assert!(!all_inert.issue_is_empty(), "and that is exactly what the log must say");
    let empty =
        BlockedPrefixes::installed_under(issue(None, None, &[]), Some(&claimant), None);
    assert!(empty.issue_is_empty(), "an issue with no entries has nothing to say");
    assert!(BlockedPrefixes::default().issue_is_empty(), "nor has no supply at all");
}

/// THE OFF-BOARD TEST (AUTH-4.36 step 4b's comparand (b) as ruled
/// 2026-09-18; REG-1.69): a host's account in the registry's GLOBAL form,
/// `1.3.0.7`, is on-board under `--node-prefix 1.3` and off-board under
/// `--node-prefix 1.5` — the test runs against the prefix and never the
/// local root `1`, under which that address read as on-board on every
/// board (W2a's escalation 3). With NO prefix the test is off and every
/// operator reads as on-board. The claimant taken in the header's place
/// is never tested: it is an account of this board by construction.
#[test]
fn the_off_board_test_reads_the_node_prefix_and_never_the_local_root() {
    let (claimant, record) = ("1.0.1", "1.0.1.0.7.1");
    let (own, foreign) = (node_prefix("1.3"), node_prefix("1.5"));
    let entries = [(claimant, record), ("1.3.0.7", record)];
    let verdicts = |operator: Option<&str>, prefix: Option<&NodePrefix>| {
        BlockedPrefixes::installed_under(issue(operator, None, &entries), Some(&addr(claimant)), prefix)
            .inert
    };
    let (a, b) = (Some(Comparand::Operator), Some(Comparand::BindingWriter));
    assert_eq!(
        verdicts(Some("1.3.0.7"), Some(&own)),
        [None, a],
        "under 1.3 the operator is ON-board: (b) silent, the claimant's entry live"
    );
    assert_eq!(
        verdicts(Some("1.3.0.7"), Some(&foreign)),
        [b, a],
        "under 1.5 the same operator is OFF-board: (b) live, the served claimant exempt"
    );
    assert_eq!(
        verdicts(Some("1.3.0.7"), None),
        [None, a],
        "no node prefix: the test is off, every operator on-board"
    );
    assert_eq!(
        verdicts(None, Some(&foreign)),
        [a, None],
        "the claimant taken in the header's place is on-board by construction, whatever \
         the prefix — its local form is under no `1.N`"
    );
    let installed = BlockedPrefixes::installed_under(issue(Some("1.3.0.7"), None, &[]), None, Some(&own));
    assert_eq!(installed.node_prefix, Some(own), "the prefix the install read is kept for the log");
}

/// REG-1.69's form, at the parse: a NODE address strictly under the root
/// `1` — an org's `1.N`, a subnode beneath — and nothing else: the root
/// itself, another first component (REG-1.67), an account or document
/// address, a trailing zero, text no tumbler spells.
#[test]
fn a_node_prefix_is_a_node_address_strictly_under_the_root() {
    for ok in ["1.2", "1.3", "1.3.2", "1.1024.7"] {
        let parsed: NodePrefix =
            ok.parse().unwrap_or_else(|_| panic!("'{ok}' is a node prefix"));
        assert_eq!(parsed.address(), &addr(ok));
        assert_eq!(parsed.address().level(), Level::Node);
        assert_eq!(parsed.to_string(), ok, "and renders as the operator spelled it");
    }
    for bad in ["1", "2.4", "2", "1.3.0.7", "1.3.0.7.0.1", "1.0", "0.3", "1..3", "", "x", "1.3."] {
        assert!(bad.parse::<NodePrefix>().is_err(), "'{bad}' is not a node prefix");
    }
}

/// The log NAMES the list in force (AUTH-4.70) — the count, the header
/// as resolved, the node prefix the off-board test ran against or that
/// the test was off — and every INERT entry by name with the comparand
/// it covers (AUTH-4.36 step 4b: "ignored at install and said so in the
/// log"). Entries in force are counted, never listed.
#[test]
fn the_install_log_names_the_count_the_header_and_each_inert_entry() {
    let claimant = addr("1.0.1");
    let prefix = node_prefix("1.3");
    let list = BlockedPrefixes::installed_under(
        issue(Some("2.0.7"), None, &[("1.0.1", "1.0.1.0.9.1"), ("1.0.3", "1.0.1.0.7.1"), ("2.0.7", "1.0.1.0.11.1")]),
        Some(&claimant),
        Some(&prefix),
    );
    assert_eq!(
        list.log_lines(),
        [
            "1 of 3 entries in force, 2 inert; operator account 2.0.7 (the header's); \
             binding-writing account 1.0.1 (the claimant — the header omits it) — exempt, \
             the operator account being off-board (not under the node prefix 1.3)",
            "entry 1.0.1 (record 1.0.1.0.9.1) is INERT — it covers the board's \
             binding-writing account 1.0.1; ignored",
            "entry 2.0.7 (record 1.0.1.0.11.1) is INERT — it covers the configured \
             operator account 2.0.7; ignored",
        ]
    );
    let root = BlockedPrefixes::installed_under(
        issue(None, None, &[("1.0.3", "1.0.1.0.7.1")]),
        Some(&claimant),
        Some(&prefix),
    );
    assert_eq!(
        root.log_lines(),
        ["1 of 1 entries in force, 0 inert; operator account 1.0.1 (the claimant — the \
          header names none); binding-writing account not a comparand (the operator \
          account is an account of this board — under the node prefix 1.3, or the \
          claimant taken in the header's place — or there is none)"]
    );
    // No node prefix: the test is off, and the header line says so ONCE
    // — per install, not per entry — whatever the header names.
    let untold = BlockedPrefixes::installed_under(
        issue(Some("1.3.0.7"), None, &[("1.0.1", "1.0.1.0.9.1"), ("1.0.3", "1.0.1.0.7.1")]),
        Some(&claimant),
        None,
    );
    assert_eq!(
        untold.log_lines(),
        ["2 of 2 entries in force, 0 inert; operator account 1.3.0.7 (the header's); \
          binding-writing account not a comparand (no --node-prefix: the off-board test \
          is off; a hosted board must supply one)"]
    );
    let unclaimed = BlockedPrefixes::installed_under(issue(None, None, &[]), None, None);
    assert!(
        unclaimed.log_lines()[0].contains("operator account none (the header names none, and the board is unclaimed)"),
        "{:?}",
        unclaimed.log_lines()
    );
}

/// The supply's BYTE CAP at both ends: a file AT the cap is read and
/// parsed, one byte past it is refused unread. The at-cap half is the
/// load-bearing one — a `>` that became a `>=` would refuse a list the
/// budget admits — and the padding is insignificant whitespace, so what
/// the refusal answers is the SIZE and not the grammar.
#[test]
fn a_supply_past_the_byte_cap_is_refused_unread() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("blocked.json");
    let mut at_cap = br#"{"entries":[]}"#.to_vec();
    at_cap.resize(MAX_BLOCKED_SUPPLY_BYTES, b' ');
    std::fs::write(&path, &at_cap).expect("write");
    let (_supply, issue) = BlockedSupply::open(&path).expect("a supply at the cap is read");
    assert_eq!(issue, BlockedIssue::default(), "and parses to the empty list");

    let mut over = at_cap;
    over.push(b' ');
    std::fs::write(&path, &over).expect("write");
    let e = BlockedSupply::open(&path).expect_err("one byte past the cap is refused");
    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "the channel's one refusal kind");
    assert!(e.to_string().contains("supply cap"), "the refusal names the cap: {e}");
}

/// The supply file's grammar: one strict JSON object. `entries` is
/// required (an empty array IS the empty list), the two header fields
/// are optional and have ONE spelling of "none" — absence — and an
/// unread field, a torn object, or an address no tumbler spells is a
/// named refusal, never a list quietly shorter than the one issued.
#[test]
fn the_supply_file_is_one_strict_json_object() {
    let parsed = parse_issue(
        br#"{"operator":"2.0.7","binding_writer":"1.0.2","entries":[{"prefix":"1.0.3","record":"1.0.1.0.7.1"}]}"#,
    )
    .expect("the whole grammar");
    assert_eq!(parsed, issue(Some("2.0.7"), Some("1.0.2"), &[("1.0.3", "1.0.1.0.7.1")]));
    assert_eq!(parse_issue(br#"{"entries":[]}"#), Ok(BlockedIssue::default()), "the empty list");
    for (bad, why) in [
        (&br#"{}"#[..], "entries is required"),
        (br#"[]"#, "not an object"),
        (br#"{"entries":[{"prefix":"1.0.3","#, "a torn object does not parse"),
        (br#"{"entries":[],"lifted":true}"#, "an unread field"),
        (br#"{"operator":null,"entries":[]}"#, "absence is the one spelling of none"),
        (br#"{"entries":[{"prefix":"1.0.3"}]}"#, "an entry without its record"),
        (br#"{"entries":[{"prefix":"1.0.3","record":"1.0.1.0.7.1","note":"x"}]}"#, "an unread entry field"),
        (br#"{"entries":[{"prefix":"1..3","record":"1.0.1.0.7.1"}]}"#, "not a tumbler"),
        (br#"{"entries":[{"prefix":"1.0.0.3","record":"1.0.1.0.7.1"}]}"#, "not T4-valid"),
        (br#"{"entries":["1.0.3"]}"#, "an entry that is not an object"),
    ] {
        assert!(parse_issue(bad).is_err(), "{why}: {}", String::from_utf8_lossy(bad));
    }
}
