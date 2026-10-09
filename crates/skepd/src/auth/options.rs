//! The session layer's configuration: the options an operator supplies,
//! what the daemon resolves from them once a port is bound, and the board's
//! mode read off them.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use skep_util::source::Source;

use super::blocked::BlockedPrefixes;
use super::lock::LockWrite;
use super::origin::{signed_origins, Origin};
use super::prefix::NodePrefix;

/// The daemon's session-layer configuration, as the operator supplies it:
/// the local-trust flag (Phase A default ON — a hosted image must set it
/// AFFIRMATIVELY false, AUTH-4.57 (i)), the configured origins (AUTH-4.7:
/// configure what the board is actually reachable at), the blocked-prefix
/// supply, the node prefix, and the ONE dev setting signed ops added —
/// `allow_preview_keys` (AUTH-1.44), default OFF; and beside the flag and
/// the prefix WHERE each came from (`local_trust_source`,
/// `node_prefix_source`), so the open's report names each setting with its
/// source (`operations.md` §1 THE OPEN's REPORT; §1.1 rows 19 and m14).
///
/// `#[non_exhaustive]`, paired with the [`Default`] below: a caller starts
/// from the defaults and sets what it means to change, so a knob added
/// later arrives at its default rather than breaking every construction.
/// The OPPOSITE call from [`crate::HttpRequest`], deliberately — a field
/// there is a fact about the request that a caller must supply, and one
/// added silently would be answered from a default the caller never chose;
/// here every field is an operator's option and abstention is the safe
/// state, which is the whole shape of `local_trust`'s own ruling.
///
/// From outside this crate that starting-and-setting is the MUTATION form:
/// `#[non_exhaustive]` bars a struct expression, functional update syntax
/// (`..Default::default()`) included, so the shape this file's own tests use
/// is in-crate only.
///
/// ```
/// use skepd::AuthOptions;
///
/// let mut opts = AuthOptions::default();
/// opts.local_trust = false;
/// // …and whatever else this caller means to change; a knob added later
/// // arrives at its own default rather than at whatever a literal omitted.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthOptions {
    /// Bare binds honored on loopback after the claim (CLAIMED-PERMISSIVE)
    /// when true; ENFORCING when false. Pre-claim the flag is not consulted:
    /// the board is UNCLAIMED whatever it says ([`Mode::of`], AUTH-4.26).
    pub local_trust: bool,
    /// Where `local_trust` came from — the default, the flag
    /// (`--local-trust` / `--no-local-trust`) or the variable
    /// (`SKEPD_LOCAL_TRUST`) — as the binary's parse recorded it, which the
    /// open's `auth:` line names beside the flag's value (§1.1 m14);
    /// `Source::Default` from a caller that sets the flag and names no
    /// source, which the line then says.
    pub local_trust_source: Source,
    /// The CONFIGURED origin set — the signed arm's whole set once claimed;
    /// unioned with the loopback defaults on the bare arm.
    ///
    /// Deliberately not `origins`: `/health` publishes a field of that name
    /// (AUTH-6.13) and it is the BARE set — configured ∪ the three loopback
    /// defaults — so copying that field back into this one re-admits the
    /// defaults the claim-time drop exists to remove.
    pub configured: Vec<Origin>,
    /// The BLOCKED-PREFIX LIST's supply (AUTH-1.44, AUTH-4.70): the file
    /// the operator maintains from the standing takedown records of
    /// the board it fronts — `--blocked-prefixes <FILE>`. SUPPLIED AT EVERY
    /// START, as `configured` is: a named file is read at open, and one
    /// that cannot be read or is not a list FAILS the open, so no restart
    /// starts the daemon on an empty list the standing records do not
    /// support. RE-ISSUED while the daemon runs by replacing the file; the
    /// format and the re-read are `BlockedSupply`'s. `None` is a board
    /// whose operator supplies none — the notebook — and no prefix is
    /// blocked.
    ///
    /// Deliberately not `blocked_prefixes`, as `configured` is deliberately
    /// not `origins`: `blocked_prefixes` is `AuthConfig`'s read of the LIST
    /// IN FORCE, and this is the path of the FILE that supplies it.
    /// The flag keeps the list's name — `--blocked-prefixes` is what an
    /// operator thinks about — and the field keeps the file's.
    pub blocked_supply_path: Option<PathBuf>,
    /// The board's full NODE PREFIX in the registry — `--node-prefix 1.N`
    /// (REG-1.69): EGRESS AND ASSERTION CONFIG, per daemon, supplied at
    /// every start as `configured` is and never a journaled genesis fact,
    /// which is what lets the same board answer to a successor under a
    /// fresh prefix — taken by a reconfigure and restart (REG-1.70). In no
    /// record, journal, sidecar or fold. The ONE thing this daemon decides
    /// by it: the blocked-prefix list's OFF-BOARD test
    /// ([`BlockedPrefixes::installed_under`]) — whether the list's configured
    /// operator account is an account of this board — read against this
    /// prefix and never against the local root `1`, under which every
    /// address in the registry's global form would read as this board's own
    /// (REG-1.66). `None` is a board that has not been told its prefix: the
    /// notebook, or a hosted board mis-launched — and that test is then OFF,
    /// every operator reading as on-board, the start-up log saying so.
    ///
    /// The FORM is [`NodePrefix`]'s, carried by the type: a `Some` is a node
    /// address strictly under the root because nothing else can be built.
    pub node_prefix: Option<NodePrefix>,
    /// Where `node_prefix` came from — the flag (`--node-prefix`) or the
    /// variable (`SKEPD_NODE_PREFIX`); `Source::Default` where none was
    /// supplied, and from a caller that sets a prefix and names no source —
    /// which the start-up line (`AuthConfig::node_prefix_line`) names beside
    /// the prefix (§1.1 row 19).
    pub node_prefix_source: Source,
    /// THE DEV SETTING `allow_preview_keys` — `--allow-preview-keys`
    /// (AUTH-1.44; the hybrid-only launch's Q5, owner 2026-09-26 "b"; AUTH
    /// RES-206): the daemon REFUSES ENROLLMENT of a TAG-3 key — a key of the
    /// PREVIEW row, `fndsa512-preview-ed25519` — as `preview_key`, slot (4)'s
    /// FIRST token (AUTH-3.44, AUTH-3.56), in EVERY enrolment record, a
    /// genesis included, UNLESS this is on; the test fixtures run with it on.
    /// Default OFF: tag 3 never reaches a served board. It gates ENROLLMENT
    /// and nothing else — tag-3 VERIFICATION stays compiled in (the
    /// frozen-tag rule), the fold admits the row's keys as syntax, and a
    /// tag-3 key already enrolled opens sessions and signs entries as any
    /// other. Daemon config, never board state: in no record, journal,
    /// sidecar or fold, and `/health` publishes nothing of it.
    pub allow_preview_keys: bool,
}

impl Default for AuthOptions {
    fn default() -> AuthOptions {
        AuthOptions {
            local_trust: true,
            local_trust_source: Source::Default,
            configured: Vec::new(),
            blocked_supply_path: None,
            node_prefix: None,
            node_prefix_source: Source::Default,
            allow_preview_keys: false,
        }
    }
}

/// The resolved configuration the auth surface reads: options plus the
/// BOUND port, which exists only once the listener does. `serve` sets it;
/// a socket-free embedder that wants origin-set behavior calls
/// [`crate::Daemon::bind_auth_port`] itself. Until set there is no port and
/// so no loopback defaults — origin membership then admits only what an
/// explicit `--origin` names, which is the honest degenerate for a daemon
/// that is not serving, and which [`AuthConfig::port`] says in its type
/// rather than through a sentinel every reader has to carve around.
///
/// Beside the members the BLOCKED-PREFIX LIST (AUTH-1.44): daemon config as
/// `configured` is, never board state — in no record, journal, sidecar or
/// fold — and the one member RE-ISSUED WHILE THE DAEMON RUNS, which is why
/// it alone sits behind a lock. Read through [`AuthConfig::blocked_prefixes`]
/// and replaced whole through [`AuthConfig::install_blocked`], under the
/// credential write lock — both here, beside the cell they are the only
/// doors to. And the NODE PREFIX (REG-1.69), fixed at open as `configured`
/// is: a fresh one is a reconfigure and restart (REG-1.70), so it sits
/// behind no lock, and every install of the list reads the one in force.
pub(crate) struct AuthConfig {
    pub local_trust: bool,
    /// [`AuthOptions::local_trust_source`], as supplied — what the `auth:`
    /// line reads beside the flag.
    local_trust_source: Source,
    pub configured: BTreeSet<Origin>,
    port: OnceLock<u16>,
    /// The list IN FORCE, read through [`AuthConfig::blocked_prefixes`] and
    /// replaced through [`AuthConfig::install_blocked`] alone — private, so
    /// that guard-taking door is the ONLY writer. The `RwLock` makes the swap
    /// of one pointer safe for readers that hold no credential lock (the
    /// handshake, the route level's `resolve`); what ORDERS an install
    /// against the writes it ends is the credential write lock its installer
    /// holds, and names.
    blocked: parking_lot::RwLock<Arc<BlockedPrefixes>>,
    /// [`AuthOptions::node_prefix`], as supplied; `None` where the daemon
    /// was told none.
    node_prefix: Option<NodePrefix>,
    /// [`AuthOptions::node_prefix_source`], as supplied — what the start-up
    /// line reads beside the prefix.
    node_prefix_source: Source,
    /// [`AuthOptions::allow_preview_keys`], as supplied — the ONE setting
    /// the precheck's slot (4) reads (AUTH-3.15 as RES-206 landed it).
    pub allow_preview_keys: bool,
}

impl AuthConfig {
    pub(super) fn new(opts: AuthOptions) -> AuthConfig {
        AuthConfig {
            local_trust: opts.local_trust,
            local_trust_source: opts.local_trust_source,
            configured: opts.configured.into_iter().collect(),
            port: OnceLock::new(),
            // Empty until [`AuthState::open`] installs the start-up supply.
            blocked: parking_lot::RwLock::new(Arc::new(BlockedPrefixes::default())),
            node_prefix: opts.node_prefix,
            node_prefix_source: opts.node_prefix_source,
            allow_preview_keys: opts.allow_preview_keys,
        }
    }

    /// The node prefix in force (REG-1.69), or `None` where the daemon was
    /// told none — the one reader is the list's install, and the log.
    pub fn node_prefix(&self) -> Option<&NodePrefix> {
        self.node_prefix.as_ref()
    }

    /// The start-up line's text (`operations.md` §1.1 row 19): the node
    /// prefix in force with its SOURCE — `(--node-prefix)` or
    /// `(SKEPD_NODE_PREFIX)`, the name alone, the line already saying the
    /// value; `(the default)` from a caller that set one and named no source
    /// — or its absence; said once, at start, whether or not a list is
    /// supplied, because a hosted board launched without its prefix has its
    /// off-board test OFF and would otherwise learn so only at its first
    /// install.
    pub fn node_prefix_line(&self) -> String {
        match &self.node_prefix {
            Some(prefix) => format!(
                "node prefix {prefix} ({}): egress and assertion config, never journaled; the \
                 blocked-prefix list's off-board test runs against it",
                self.node_prefix_source.words("--node-prefix", "SKEPD_NODE_PREFIX")
            ),
            None => "no --node-prefix: the off-board test is off (every operator account reads \
                     as this board's own); a hosted board must supply one"
                .to_string(),
        }
    }

    /// The board's mode at a snapshot whose claim is `claimed` — [`Mode::of`]
    /// over this config, for the sites outside this module that say the mode
    /// on the operator stream and can name the words but not the type.
    pub fn mode(&self, claimed: bool) -> Mode {
        Mode::of(self, claimed)
    }

    /// THE OPEN's-REPORT `auth:` LINE's text (`operations.md` §1.1 m14),
    /// rendered HERE because this is where its state lives — the convention
    /// this module keeps for everything it publishes, the `/health` object
    /// included: `auth: {unclaimed | CLAIMED-ENFORCING | CLAIMED-PERMISSIVE}
    /// (--local-trust {on|off}, {source}); configured origins {list | none};
    /// signed origins {list}` — the mode derived from the pair as AUTH-5.86
    /// derives it ([`Mode::of`]), the flag's value and its source beside it,
    /// the configured set, and the signed set as the handshake admits it at
    /// this claim ([`signed_origins`]: the configured set alone once
    /// claimed, else the bare set — the loopback defaults of the BOUND port
    /// with the configured). Each set in one spelling: the origins'
    /// canonical text, in the set's order, `none` where the set is empty —
    /// a claimed board with no configured origin has an empty signed set,
    /// which row 17's warning names the consequence of. The one line that
    /// names a mistyped `--origin` on an ENFORCING board, where every signed
    /// session is otherwise refused in silence.
    pub fn auth_line(&self, claimed: bool) -> String {
        let (flag, variable) = if self.local_trust {
            ("--local-trust", "SKEPD_LOCAL_TRUST=true")
        } else {
            ("--no-local-trust", "SKEPD_LOCAL_TRUST=false")
        };
        let list = |set: &BTreeSet<Origin>| -> String {
            if set.is_empty() {
                "none".to_string()
            } else {
                set.iter().map(Origin::as_str).collect::<Vec<_>>().join(", ")
            }
        };
        format!(
            "auth: {} (--local-trust {}, {}); configured origins {}; signed origins {}",
            Mode::of(self, claimed),
            if self.local_trust { "on" } else { "off" },
            self.local_trust_source.words(flag, variable),
            list(&self.configured),
            list(&signed_origins(self, claimed)),
        )
    }

    /// THE LIST IN FORCE — AUTH-4.36 step 4b's `blocked_prefixes(cfg)`, a
    /// pure read of the cell [`AuthConfig::install_blocked`] replaces. By
    /// value (one pointer clone), so no reader holds the cell's lock across
    /// its own work and an install never waits on a handshake's verify loop.
    pub fn blocked_prefixes(&self) -> Arc<BlockedPrefixes> {
        Arc::clone(&self.blocked.read())
    }

    /// THE INSTALL (AUTH-4.70): the list REPLACED WHOLE, atomically, under
    /// the credential write lock the caller holds and names here (AUTH-3.3)
    /// — that install being the list's COMMIT. The guard is the obligation,
    /// not a decoration: every session-authenticated write re-resolves
    /// under that lock, so a covered session's write that took the lock
    /// first lands BEFORE this install and one arriving after meets its
    /// death (AUTH-4.63's second trigger) — no `/changes` entry of a killed
    /// session carries a position after it.
    pub(super) fn install_blocked(&self, _lock: &LockWrite<'_>, list: BlockedPrefixes) {
        *self.blocked.write() = Arc::new(list);
    }

    /// [`PortAlreadyBound`] carries the port ALREADY BOUND — the number
    /// every live session's origin set was established against, which is
    /// what a caller disagreeing about it needs to be told. The value is set
    /// ONCE, so a second bind would otherwise be a silent no-op.
    /// [`crate::serve`] and a socket-free embedder are the two callers, and
    /// they are exclusive by design.
    ///
    /// PRECONDITION: `port != 0`, and it stops here loudly rather than being
    /// admitted — the posture [`crate::serve`] takes on a zero worker count,
    /// for the same reason: it is a caller's bug and not an outcome.
    /// [`AuthConfig::port`] states that zero is not a port this daemon can
    /// serve on, and zero is the one value that makes [`Origin::from_parts`]
    /// build text [`Origin::parse`] refuses — `http://127.0.0.1:0` fails the
    /// leading-zero clause. Admitted, it fires that constructor's debug
    /// assert on every request that reads a derived origin, and in release
    /// publishes a `/health` origin set whose members this daemon's own
    /// parser rejects and no `Origin` header can match. `serve` cannot reach
    /// it (the OS never assigns port 0 to a bound listener), so the one
    /// caller is the socket-free embedder.
    pub fn bind_port(&self, port: u16) -> Result<(), PortAlreadyBound> {
        assert!(port != 0, "port 0 is not a port this daemon can serve on");
        self.port.set(port).map_err(|_| {
            PortAlreadyBound(self.port().expect("set once, so a refusal means one is bound"))
        })
    }

    /// The bound port, or `None` while no listener exists. An `Option`
    /// rather than a zero: port 0 is not a port this daemon can serve on,
    /// and a sentinel would make every reader of a derived origin carve the
    /// case out for itself.
    pub fn port(&self) -> Option<u16> {
        self.port.get().copied()
    }
}

/// [`crate::Daemon::bind_auth_port`] refused: a port is ALREADY BOUND.
/// Carries that port — the number every live session's origin set was
/// established against, which is what a caller disagreeing about it needs
/// to be told — and not the number it offered, which it already has.
///
/// A named error rather than a bare `u16`, for
/// [`NotCanonical`](super::NotCanonical)'s reason:
/// this is an ecosystem door, and only a type carrying `Display` and
/// `std::error::Error` composes with `?` in a caller's own error type. A
/// caller cannot add either impl to an integer, and an `Err(8642)` says
/// nothing about which of the two ports it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortAlreadyBound(u16);

impl PortAlreadyBound {
    /// The port already bound.
    pub fn port(self) -> u16 {
        self.0
    }
}

impl fmt::Display for PortAlreadyBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the auth port is already bound to {}", self.0)
    }
}

impl std::error::Error for PortAlreadyBound {}

/// The board's MODE (wire.md §Identity: "the board is always in exactly one
/// of three MODES, derived from two facts `GET /health` publishes"). The ONE
/// place the corpus's three names are said in the code rather than
/// re-derived as a conjunction of `claimed` and `local_trust`.
///
/// UNCLAIMED admits only the claim ceremony's own write shapes and honors
/// bare loopback binds; CLAIMED-PERMISSIVE honors them still (the default's
/// disclosed cost, which [`super::origin::Warning::ClaimedWithLocalTrust`] names);
/// ENFORCING refuses every bare session, so only signed sessions write.
///
/// Derived and never stored: the claim lives in the identity fold and the
/// flag in [`AuthConfig`], so a mode value is always a reading of the pair
/// as of one snapshot. The wire publishes the PAIR and deliberately no
/// `mode` field (AUTH-6.13), which is why this type is the daemon's and not
/// the wire's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Unclaimed,
    ClaimedPermissive,
    Enforcing,
}

impl Mode {
    /// The mode this config is in at a snapshot whose claim is `claimed` —
    /// the pair, read once, so a caller states the mode it means rather than
    /// the conjunction that computes it.
    pub fn of(cfg: &AuthConfig, claimed: bool) -> Mode {
        match (claimed, cfg.local_trust) {
            // Pre-claim the flag is not consulted (AUTH-4.26).
            (false, _) => Mode::Unclaimed,
            (true, true) => Mode::ClaimedPermissive,
            (true, false) => Mode::Enforcing,
        }
    }
}

/// The mode as the operator stream spells it (`operations.md` §1.1 m14):
/// `unclaimed`, `CLAIMED-PERMISSIVE`, `CLAIMED-ENFORCING` — the two claimed
/// modes in capitals, the design's own spelling, so the `auth:` line at
/// start and the flip's landing line say one word for one mode.
impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Unclaimed => "unclaimed",
            Mode::ClaimedPermissive => "CLAIMED-PERMISSIVE",
            Mode::Enforcing => "CLAIMED-ENFORCING",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE MODE's WORDS (m14): one spelling per mode, the design's own.
    #[test]
    fn each_mode_spells_its_own_word() {
        assert_eq!(Mode::Unclaimed.to_string(), "unclaimed");
        assert_eq!(Mode::ClaimedPermissive.to_string(), "CLAIMED-PERMISSIVE");
        assert_eq!(Mode::Enforcing.to_string(), "CLAIMED-ENFORCING");
    }

    /// THE `auth:` LINE's WORDS (m14) at fixed figures: an unclaimed board
    /// under the defaults names the bare set — the bound port's three
    /// loopback defaults — as its signed set and no configured origin; a
    /// claimed board with the flag off by its flag names its mode
    /// CLAIMED-ENFORCING and the configured set alone, in the set's order;
    /// one claimed with the flag on by its variable names
    /// CLAIMED-PERMISSIVE; and a claimed board with no configured origin
    /// says `none` for both sets. The source's words are the setting's,
    /// `(--local-trust {on|off}, {source})` as m14 spells them.
    #[test]
    fn the_auth_line_names_the_mode_the_flag_with_its_source_and_the_two_sets() {
        let cfg = AuthConfig::new(AuthOptions::default());
        cfg.bind_port(8642).expect("binds once");
        assert_eq!(
            cfg.auth_line(false),
            "auth: unclaimed (--local-trust on, the default); configured origins none; signed \
             origins http://127.0.0.1:8642, http://[::1]:8642, http://localhost:8642"
        );
        let configured = |s: &str| Origin::parse(s).expect("canonical");
        let enforcing = AuthConfig::new(AuthOptions {
            local_trust: false,
            local_trust_source: Source::Flag,
            configured: vec![
                configured("https://board.example"),
                configured("http://127.0.0.1:8642"),
            ],
            ..AuthOptions::default()
        });
        enforcing.bind_port(8642).expect("binds once");
        assert_eq!(
            enforcing.auth_line(true),
            "auth: CLAIMED-ENFORCING (--local-trust off, --no-local-trust); configured origins \
             http://127.0.0.1:8642, https://board.example; signed origins http://127.0.0.1:8642, \
             https://board.example"
        );
        let permissive = AuthConfig::new(AuthOptions {
            local_trust: true,
            local_trust_source: Source::Env,
            configured: vec![configured("https://board.example")],
            ..AuthOptions::default()
        });
        permissive.bind_port(443).expect("binds once");
        assert_eq!(
            permissive.auth_line(true),
            "auth: CLAIMED-PERMISSIVE (--local-trust on, SKEPD_LOCAL_TRUST=true); configured \
             origins https://board.example; signed origins https://board.example"
        );
        let unconfigured = AuthConfig::new(AuthOptions {
            local_trust: false,
            local_trust_source: Source::Env,
            ..AuthOptions::default()
        });
        unconfigured.bind_port(8642).expect("binds once");
        assert_eq!(
            unconfigured.auth_line(true),
            "auth: CLAIMED-ENFORCING (--local-trust off, SKEPD_LOCAL_TRUST=false); configured \
             origins none; signed origins none"
        );
    }

    /// THE NODE PREFIX's LINE (row 19) names its source: the flag, the
    /// variable by its bare name, and the default's phrase where a caller
    /// set a prefix and named no source; a board told none keeps its one
    /// sentence.
    #[test]
    fn the_node_prefix_line_names_the_prefix_with_its_source() {
        let at = |source: Source| {
            AuthConfig::new(AuthOptions {
                node_prefix: Some("1.3".parse().expect("a node prefix")),
                node_prefix_source: source,
                ..AuthOptions::default()
            })
            .node_prefix_line()
        };
        let rest = ": egress and assertion config, never journaled; the blocked-prefix list's \
                    off-board test runs against it";
        assert_eq!(at(Source::Flag), format!("node prefix 1.3 (--node-prefix){rest}"));
        assert_eq!(at(Source::Env), format!("node prefix 1.3 (SKEPD_NODE_PREFIX){rest}"));
        assert_eq!(at(Source::Default), format!("node prefix 1.3 (the default){rest}"));
        assert_eq!(
            AuthConfig::new(AuthOptions::default()).node_prefix_line(),
            "no --node-prefix: the off-board test is off (every operator account reads as this \
             board's own); a hosted board must supply one"
        );
    }

    /// [`AuthConfig::bind_port`] refuses a second bind and names the port
    /// already bound — the number every live session's origin set was
    /// established against, which is what the second caller needs told.
    #[test]
    fn a_second_bind_is_refused_and_names_the_bound_port() {
        let cfg = AuthConfig::new(AuthOptions::default());
        cfg.bind_port(8642).expect("a fresh config binds once");
        assert_eq!(cfg.port(), Some(8642));
        assert_eq!(
            cfg.bind_port(9999),
            Err(PortAlreadyBound(8642)),
            "the bound port, not the refused one"
        );
        assert_eq!(cfg.port(), Some(8642), "and the binding did not move");
    }

    /// Port 0 is the one value from which
    /// [`loopback_defaults`](crate::auth::origin::loopback_defaults) derives
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

    /// THE LIST IN FORCE has its two doors on the cell that holds it: a fresh
    /// config answers the empty list, and what an install under the
    /// credential write lock puts in is what the next read answers.
    #[test]
    fn the_list_in_force_is_read_where_it_is_installed() {
        use super::super::blocked::{BlockedEntry, BlockedIssue};
        use super::super::lock::CredentialLock;
        use crate::codec::wire_address;

        let cfg = AuthConfig::new(AuthOptions::default());
        assert!(cfg.blocked_prefixes().issue_is_empty(), "a fresh config holds no list");
        let prefix = wire_address("1.0.3").expect("an account address");
        let record = wire_address("1.0.1.0.7.1").expect("a record's address");
        let entry = BlockedEntry { prefix: prefix.clone(), record: record.clone() };
        let issue = BlockedIssue { entries: vec![entry], ..BlockedIssue::default() };
        let list = BlockedPrefixes::installed_under(issue, None, None);
        cfg.install_blocked(&CredentialLock::new().write(), list);
        assert_eq!(
            cfg.blocked_prefixes().covers(&prefix),
            Some(&record),
            "the read answers what the install put in"
        );
    }
}
