use super::*;
use crate::codec::wire_address;
use skep_address::{Address, Level};

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
