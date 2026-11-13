//! `skep resolve`, the eighteenth command: the board an address lives on.
//!
//! A cross-board address is one global tumbler. Its node field is the
//! prefix of the org that holds it (REG-1.62), and the registry says which
//! board answers to that prefix by one link (REG-3.7); the rest of the
//! address is read at that board. This command takes the address
//! (`--address`, as the wire spells one), resolves its node field through
//! the registry the root hint names, and prints the board to dial and the
//! address in that board's local form, the prefix swapped for `1`
//! (REG-1.63).
//!
//! The root hint is a setting (REG-3.2): `--root-hint`, or `SKEP_ROOT_HINT`
//! where no flag names one, the line `skep hint` prints. It is required
//! and has no default: the hint a build ships with is decided at launch
//! (REG-3.72). The registry's roots are the hint's alone (REG-3.3), so
//! `--board` is not consulted, and neither are `--key` and `--principal`:
//! the registry is read as a guest, over the dialer a registry mirror reads
//! through (`resolve::mirror_dialer`), an `https` root and an `http` one
//! alike.
//!
//! The mirror lives beside the keys: `<store>/registry/<genesis>/`, the
//! store the key store's directory (`--dir`, `SKEP_KEYSTORE`, else
//! `~/.skep`) and `<genesis>` the hint's genesis fingerprint, 64 lowercase
//! hex, so two registries keep two copies. Nothing under `keys/` or in
//! `bindings` is read or written. Every run opens the mirror against the
//! hint's root, which reads the registry to its head before the walk — a
//! mirror applies no TTL and remembers nothing as absent (REG-3.10) — so a
//! binding or a deposit made since the last run is seen; where the root
//! cannot be read the run refuses, and answers nothing from the copy.
//!
//! Every outcome is a named state (REG-3.80), under the name the resolver
//! spells it by. BOUND is exit 0: stdout carries one line, the origin of
//! the endpoint member the walk would dial and then the local address,
//! where the address names a place on that board — a bare prefix prints the
//! origin alone — and stderr names the face, the prefix and its account.
//! Every other face the walk answers — UNREGISTERED, RETIRED-WITH-HISTORY,
//! BOUND-BUT-UNREACHABLE with its cause, unreachable-by-policy with its
//! term, THE DIAL NOT MADE with its kind, and THE HOP NOT MADE with its
//! parent's face, a node field deeper than any standing on the registry
//! being resolved whole and never cut another way (REG-3.82) — is a halt,
//! exit 3, with nothing on stdout: its block opens with the face's name and
//! carries the facts the face does. `--json` puts the face and its facts on
//! stdout as one object at every face, the exit code unchanged. Two faces
//! are read at the dial and the hello, which this command does not make,
//! and are not answered here: BOUND-BUT-DISCLAIMED (REG-3.81) and the
//! live-enforcement face (REG-3.84).
//!
//! An address or a hint that does not read is a usage refusal, exit 2,
//! before any socket opens and before the mirror's directory is made; a
//! root that refused a read is exit 1, and one that did not answer exit 4;
//! a copy that does not read, a root that does not answer for the copy
//! held and a root of another realm than the hint's are halts naming the
//! mirror's directory, exit 3. No person door: the command runs without a
//! terminal.

use std::sync::Arc;

use skep_address::Address;
use skep_client::halt::Halt;
use skep_client::resolve::{global_address, mirror_dialer, mirror_home, resolve_address, MemberOutcome, Opened, Resolution, Resolved, Standing, SystemResolver, Term, Transports, Unreachable};

use super::{data, talk, Stop};
use crate::args::{CommandLine, Usage};

pub fn resolve(c: &CommandLine) -> Result<(), Stop> {
    // The line's own shape first, whole: nothing is dialed and no directory
    // is made for a line that does not read.
    let address = asked(c)?;
    let hint = c.root_hint()?;
    let dir = mirror_home(&c.store_dir()?, &hint);
    let roots: Vec<&str> = hint.origins().iter().map(|root| root.as_str()).collect();
    // Said before the read: the directory is made ahead of the dial, so a
    // refusal past this line leaves it standing, named here.
    talk(format!("reading the registry the root hint names ({}) as a guest; its mirror is kept under {}", roots.join(", then "), dir.display()));
    let resolved = resolve_address(Arc::new(mirror_dialer()), &hint, &dir, &address, &SystemResolver, &Transports::default()).map_err(|halt| {
        // A root not read is the halt family's own member, whose act names
        // the board a command dials; here that board is the hint's root.
        if matches!(halt, Halt::Dial(_) | Halt::Refused(_)) {
            talk(UNREAD);
        }
        if matches!(&halt, Halt::Refused(refused) if refused.code == "history_reclaimed") {
            talk(format!("{RECLAIMED}: where the copy held under {} is the cause, move that directory aside and run this again, and the registry is read afresh from its genesis (REG-3.12)", dir.display()));
        }
        halt
    })?;
    talk(read_said(&resolved));
    if c.switch("--json") {
        data(resolved.object().to_string())?;
    } else if let Some(line) = resolved.line() {
        // The one line, and nothing else on stdout: the board to dial.
        data(line)?;
    }
    match surfaced(&resolved.resolution) {
        Some(halt) => Err(halt.into()),
        None => {
            talk(bound_said(&resolved.resolution, resolved.local.as_ref()));
            Ok(())
        }
    }
}

/// What is said where the registry could not be read to its head.
///
/// Nothing is resolved then, and nothing is answered from the copy a run
/// before this one left: a mirror answers as of the registry's head or not
/// at all (REG-3.10). The root is the root hint's (REG-3.3), which this
/// command reads where the others read `--board`.
const UNREAD: &str = "the registry was not read to its head, so nothing is resolved, and no answer is given from the copy held (REG-3.10); its root \
     is the root hint's — --root-hint, or SKEP_ROOT_HINT where no flag is given — which this command reads in --board's place";

/// What is said where the registry refused a read as reclaimed.
///
/// A mirror checks a held copy against the root at the heads it was read
/// to (REG-3.18), and reads a record no version arranges at the record's
/// own position; a registry that reclaims its journal answers neither
/// below its floor. The line names the two, and the caller adds the act
/// with the directory: a copy moved aside is read afresh from genesis.
const RECLAIMED: &str = "the registry has reclaimed history the mirror asked for — a head this copy was read to, or a record's own position";

/// Returns the address `--address` names, read as the wire spells one.
///
/// # Errors
///
/// A usage refusal where the flag is absent, or its value is no address.
fn asked(c: &CommandLine) -> Result<Address, Usage> {
    let text = c.value("--address").ok_or_else(|| Usage("--address is required: the cross-board address to resolve, one global tumbler (a bare prefix resolves the prefix alone)".into()))?;
    global_address(text).ok_or_else(|| Usage(format!("--address: '{text}' is not an address (the wire's dotted spelling)")))
}

/// Returns how the registry was read for this answer, as one line of talk.
///
/// It names the root that answered, the head the mirror was read to, and
/// how the copy came to hold its base at this run (REG-3.12, REG-3.18).
fn read_said(resolved: &Resolved) -> String {
    let copy = match &resolved.opened {
        Opened::Bootstrapped => "the copy read from the registry's genesis (REG-3.12)".to_string(),
        Opened::Resumed { checked_rows } => format!("the copy held here resumed, its {} checked against the root first (REG-3.18)", count(*checked_rows, "row")),
        Opened::Rebootstrapped { retired } => format!("the copy read afresh from the registry's genesis, one of another genesis set aside as {} (REG-3.17)", retired.display()),
        Opened::Rebuilt => "the copy rebuilt with no board dialed".to_string(),
    };
    let at = resolved.root.as_ref().map_or(String::new(), |root| format!(" at {root}"));
    format!("registry read{at} to its head, position {}: {copy}", resolved.head)
}

/// Returns BOUND's talk: the face, the prefix, its account and the dial.
///
/// Beside them it says where the rest of the address is read — `local`,
/// the address in the board's local form, none for a bare prefix — and the
/// account's key set, the other half of the registry's answer (REG-3.7).
fn bound_said(resolution: &Resolution, local: Option<&Address>) -> String {
    let Resolution::Bound { keys, dial, members, .. } = resolution else { return said(resolution) };
    let read = match local {
        Some(local) => format!("read {local} there, the address in that board's local form (REG-1.63)"),
        None => "a bare prefix names no place on that board".to_string(),
    };
    let keys = match keys {
        Some(keys) => format!("the account's key set holds {} as of the registry's head", count(keys.len() as u64, "key")),
        None => "the account's key set is undeterminable here: this reader could not read it".to_string(),
    };
    format!("{}: dial {}, member {} of {} in the org's order; {read}; {keys}", said(resolution), dial.origin, dial.member_index + 1, members.len())
}

/// Returns a face's state as one sentence, opening with the face's name.
///
/// The name is the resolver's own spelling of the face (REG-3.80). The
/// match names every face and has no wildcard arm, so a face the resolver
/// gains is worded here before the command builds.
fn said(resolution: &Resolution) -> String {
    let face = resolution.face();
    match resolution {
        Resolution::Unregistered { prefix } => format!("{face}: no binding on this registry names the prefix {prefix}"),
        Resolution::RetiredWithHistory { standing, .. } => format!("{face}: the prefix {} is retired — its current binding names no account", standing.prefix),
        Resolution::BoundButUnreachable { standing, .. } => format!("{face}: {}, and no endpoint of it can be dialed", bound(standing)),
        Resolution::UnreachableByPolicy { standing, .. } => format!("{face}: {}, and this resolver refuses its endpoint", bound(standing)),
        Resolution::DialNotMade { standing, .. } => format!("{face}: {}, and this resolver holds no transport for its endpoint", bound(standing)),
        Resolution::HopNotMade { prefix, parent } => {
            let reached = parent.standing().map_or(String::new(), |standing| format!(" {}", standing.prefix));
            format!("{face}: no binding on this registry names the prefix {prefix}, and the walk stops at its parent{reached}")
        }
        Resolution::Bound { standing, .. } => format!("{face}: {}", bound(standing)),
        Resolution::BoundButDisclaimed { standing, asserted_prefix } => format!("{face}: {}, and the board it names asserts the prefix {asserted_prefix}", bound(standing)),
        Resolution::LiveEnforcement { standing, .. } => format!("{face}: {}, and its board's enforcement state was read at the dial", bound(standing)),
    }
}

/// Returns a standing's clause: the prefix, and the account it is bound to.
fn bound(standing: &Standing) -> String {
    match &standing.current.record.account {
        Some(account) => format!("the prefix {} is bound to the account {account}", standing.prefix),
        None => format!("the prefix {} names no account", standing.prefix),
    }
}

/// Returns the halt a face other than BOUND comes to; `None` for BOUND.
///
/// Every outcome is a named visible state (REG-3.80): the block's state is
/// the face under its name ([`said`]), its cause the facts the face
/// carries — the history and the successor, the cause no endpoint dials,
/// the term that refused one, the kind no transport is held for, the
/// parent's own face — and its act what a person does about it. Halt and
/// surface, exit 3.
fn surfaced(resolution: &Resolution) -> Option<Halt> {
    let deposit = "the org deposits an endpoint in its own doc 1, and the next run sees it";
    let (cause, act): (String, String) = match resolution {
        Resolution::Bound { .. } => return None,
        Resolution::Unregistered { .. } => (
            "the registry was read to its head before the walk and holds no signed binding the walk honors at that prefix; nothing is remembered as absent, so a binding made later is seen at the next run (REG-3.10)".into(),
            "check that the address is the global one — a board's own addresses open with 1 only in that board's local form (REG-1.61) — and that the root hint names the registry that binds its prefix".into(),
        ),
        Resolution::RetiredWithHistory { standing, successor } => {
            let successor = match successor {
                Some(successor) => format!("its succession names the account {}{}", successor.account, successor.prefix.as_ref().map_or(String::new(), |prefix| format!(", at the prefix {prefix}"))),
                None => "no successor is named: this build reads no succession ground record, which is not to say none stands (REG-3.83)".to_string(),
            };
            (
                format!("the org existed: {} in the prefix's history, the last at position {} (link {}); {successor}", count(standing.history.len() as u64, "binding"), standing.current.position, standing.current.link),
                "a retired prefix is never bound again; where a successor is named, resolve the successor's own prefix".into(),
            )
        }
        Resolution::BoundButUnreachable { cause, members, .. } => match cause {
            Unreachable::NoEndpointYet => ("no endpoint yet: no honored endpoint deposit stands in the account's doc 1 — the interval between a binding and its org's first deposit".into(), deposit.into()),
            Unreachable::NullifiedLast => ("the last endpoint nullified: the org took its last honored deposit off the active view, and none stands before it".into(), deposit.into()),
            Unreachable::DeadOrigin { member } => (
                format!("a dead origin: {member} names a host that yields no address from this machine (endpoint rot){}", beside(members)),
                "check that the name resolves from this machine; where it does not, the org replaces the endpoint by a fresh deposit".into(),
            ),
        },
        Resolution::UnreachableByPolicy { member, term, members, .. } => match term {
            Term::Scheme => (
                format!("the scheme term (REG-3.34): {member} is neither an https origin nor a self-authenticating one{}", beside(members)),
                "the org deposits an https endpoint; a plaintext one is never dialed".into(),
            ),
            Term::Host { yielded } => {
                let yielded: Vec<String> = yielded.iter().map(ToString::to_string).collect();
                (
                    format!(
                        "the host term (REG-3.35): {member} is not globally routable — tested at {}, the address its host is or every address this resolver's own resolution of its name yielded, this resolver's yield and never the record's{}",
                        yielded.join(", "),
                        beside(members)
                    ),
                    "where those addresses are this machine's network's answer for the name, resolve from another network; otherwise the org deposits an endpoint at a routable host".into(),
                )
            }
        },
        Resolution::DialNotMade { member, kind, members, .. } => (
            format!("{member} is of the kind {}, an admitted kind whose transport this build does not hold: it was never dialed, and the org's liveness is unknown here (REG-3.34){}", kind.name(), beside(members)),
            format!("dial it with a client that holds the {} transport", kind.name()),
        ),
        Resolution::HopNotMade { prefix, parent } => (
            format!("the parent stands on this registry — {}; the binding of {prefix} is on that org's own board, which this registry's mirror does not hold (REG-3.32), so nothing is promised about {prefix} (REG-3.82)", said(parent)),
            "resolve it against the parent org's board, with a root hint that names that board".into(),
        ),
        Resolution::BoundButDisclaimed { .. } => (
            "the asserted prefix is that board's own unauthenticated claim about itself, read off its hello (REG-3.81)".into(),
            "resolve the prefix it asserts, to see what the registry binds there".into(),
        ),
        Resolution::LiveEnforcement { claimant, local_trust, .. } => (
            format!("its claimant is {}, and local trust is {local_trust} (REG-3.84)", claimant.as_ref().map_or("none".to_string(), ToString::to_string)),
            "read the board's own mode with `skep health`".into(),
        ),
    };
    Some(Halt::face(said(resolution), cause, act))
}

/// Returns every member's outcome, said beside a face that has several.
///
/// A face is its first member's (REG-3.34's one precedence), each later
/// member's outcome beside it and never in its place; an endpoint of one
/// member adds nothing.
fn beside(members: &[MemberOutcome]) -> String {
    if members.len() < 2 {
        return String::new();
    }
    let each: Vec<String> = members
        .iter()
        .map(|member| match member {
            MemberOutcome::WouldDial { origin, .. } => format!("{origin} would dial"),
            MemberOutcome::Refused { member, term: Term::Scheme } => format!("{member} refused on the scheme term"),
            MemberOutcome::Refused { member, term: Term::Host { .. } } => format!("{member} refused on the host term"),
            MemberOutcome::NotDialed { origin, kind } => format!("{origin} not dialed, no {} transport held", kind.name()),
            MemberOutcome::Dead { origin } => format!("{origin} dead, its name yielding no address"),
        })
        .collect();
    format!("; the endpoint's members in the org's order — {}", each.join(", "))
}

/// Returns `n` of `noun`, the noun plural where `n` is not one.
fn count(n: u64, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use skep_client::resolve::{BindingRecord, EndpointDial, EndpointRecord, Judged, MemberKind, RootHint, Successor, Verdict};
    use skep_identity::Fingerprint;

    use super::*;

    fn a(text: &str) -> Address {
        global_address(text).expect("an address")
    }

    fn signed(pair: &str) -> Verdict {
        Verdict::Signed(Fingerprint::parse_hex(&pair.repeat(32)).expect("64 hex"))
    }

    /// `1.5`'s standing: bound to `1.0.2`, or retired by a second binding.
    fn standing(retired: bool) -> Standing {
        let binding = |position, account: Option<&str>| Judged {
            position,
            link: a(&format!("1.0.1.0.1.0.2.{position}")),
            home: a("1.0.1.0.1"),
            record: BindingRecord { prefix: a("1.5"), account: account.map(a), replaces: None, honored: true },
            verdict: signed("ab"),
        };
        let history = if retired { vec![binding(1, Some("1.0.2")), binding(2, None)] } else { vec![binding(1, Some("1.0.2"))] };
        Standing { prefix: a("1.5"), current: history[history.len() - 1].clone(), history }
    }

    fn endpoint(origins: &[&str]) -> Judged<EndpointRecord> {
        let record = EndpointRecord { origins: origins.iter().map(ToString::to_string).collect(), replaces: None, honored: true, nullified: false };
        Judged { position: 3, link: a("1.0.2.0.1.0.2.1"), home: a("1.0.2.0.1"), record, verdict: signed("cd") }
    }

    /// Checks that every face but BOUND is a halt whose block opens with its name.
    ///
    /// One row per face the walk answers beside BOUND, and the two it does
    /// not: each is halt and surface, exit 3, its block's first line the
    /// face's own name and then its state, and its cause the facts the face
    /// carries (the mutant that words a face under another's name, or drops
    /// a face's fact, fails its row).
    #[test]
    fn every_face_but_bound_is_a_halt_whose_block_opens_with_its_name_and_carries_its_facts() {
        let bound = || standing(false);
        let onion = RootHint::parse(&format!("http://x.onion realm:{}", "ab".repeat(32))).expect("a hint").origins()[0].clone();
        let not_dialed = MemberOutcome::NotDialed { origin: onion, kind: MemberKind::Onion };
        let plain = MemberOutcome::Refused { member: "http://plain.example".into(), term: Term::Scheme };
        let unreachable = |cause| Resolution::BoundButUnreachable { standing: bound(), keys: None, endpoint: None, cause, members: Vec::new() };
        let rows: Vec<(Resolution, &[&str])> = vec![
            (Resolution::Unregistered { prefix: a("1.9") }, &["UNREGISTERED: no binding on this registry names the prefix 1.9\n", "nothing is remembered as absent", "the global one"]),
            (
                Resolution::RetiredWithHistory { standing: standing(true), successor: None },
                &["RETIRED-WITH-HISTORY: the prefix 1.5 is retired", "2 bindings in the prefix's history, the last at position 2 (link 1.0.1.0.1.0.2.2)", "no successor is named"],
            ),
            (
                Resolution::RetiredWithHistory { standing: standing(true), successor: Some(Successor { account: a("1.0.7"), prefix: Some(a("1.8")) }) },
                &["RETIRED-WITH-HISTORY: ", "its succession names the account 1.0.7, at the prefix 1.8"],
            ),
            (unreachable(Unreachable::NoEndpointYet), &["BOUND-BUT-UNREACHABLE: the prefix 1.5 is bound to the account 1.0.2, and no endpoint of it can be dialed\n", "cause: no endpoint yet: "]),
            (unreachable(Unreachable::NullifiedLast), &["BOUND-BUT-UNREACHABLE: ", "cause: the last endpoint nullified: "]),
            (unreachable(Unreachable::DeadOrigin { member: "https://dead.example".into() }), &["BOUND-BUT-UNREACHABLE: ", "cause: a dead origin: https://dead.example names a host"]),
            (
                Resolution::UnreachableByPolicy { standing: bound(), keys: None, endpoint: endpoint(&["http://plain.example", "http://x.onion"]), member: "http://plain.example".into(), term: Term::Scheme, members: vec![plain, not_dialed.clone()] },
                &["unreachable-by-policy: the prefix 1.5 is bound to the account 1.0.2", "the scheme term (REG-3.34): http://plain.example", "http://plain.example refused on the scheme term, http://x.onion not dialed, no onion transport held"],
            ),
            (
                Resolution::UnreachableByPolicy { standing: bound(), keys: None, endpoint: endpoint(&["https://loop.example"]), member: "https://loop.example".into(), term: Term::Host { yielded: vec!["127.0.0.1".parse().unwrap()] }, members: Vec::new() },
                &["unreachable-by-policy: ", "the host term (REG-3.35): https://loop.example is not globally routable — tested at 127.0.0.1,", "this resolver's yield and never the record's"],
            ),
            (
                Resolution::DialNotMade { standing: bound(), keys: None, endpoint: endpoint(&["http://x.onion"]), member: "http://x.onion".into(), kind: MemberKind::Onion, members: vec![not_dialed] },
                &["THE DIAL NOT MADE: the prefix 1.5 is bound to the account 1.0.2", "http://x.onion is of the kind onion", "act: dial it with a client that holds the onion transport"],
            ),
            (
                Resolution::HopNotMade { prefix: a("1.5.3"), parent: Box::new(unreachable(Unreachable::NoEndpointYet)) },
                &["THE HOP NOT MADE: no binding on this registry names the prefix 1.5.3, and the walk stops at its parent 1.5\n", "the parent stands on this registry — BOUND-BUT-UNREACHABLE: the prefix 1.5 is bound to the account 1.0.2", "nothing is promised about 1.5.3 (REG-3.82)"],
            ),
            (Resolution::BoundButDisclaimed { standing: bound(), asserted_prefix: "1.6".into() }, &["BOUND-BUT-DISCLAIMED: ", "asserts the prefix 1.6\n", "(REG-3.81)"]),
            (Resolution::LiveEnforcement { standing: bound(), claimant: Some(a("1.0.1")), local_trust: false }, &["the live-enforcement face: ", "its claimant is 1.0.1, and local trust is false (REG-3.84)"]),
        ];
        for (resolution, facts) in rows {
            let halt = surfaced(&resolution).unwrap_or_else(|| panic!("{} is a halt", resolution.face()));
            let block = halt.to_string();
            assert_eq!(halt.exit_code(), 3, "{block}");
            assert!(block.starts_with(&format!("{}: ", resolution.face())), "the face's own name opens its block: {block}");
            for fact in facts {
                assert!(block.contains(fact), "{}: {fact:?} in:\n{block}", resolution.face());
            }
        }
    }

    /// Checks that BOUND is no halt, and that its talk names what it found.
    ///
    /// It names the face, the prefix, its account, the member the walk
    /// would dial by its place in the org's order, where the rest of the
    /// address is read — or that a bare prefix names no place — and the key
    /// set, said as undeterminable where the reader could not read it.
    #[test]
    fn bound_is_no_halt_and_its_talk_names_the_prefix_its_account_and_the_dial() {
        let acme = RootHint::parse(&format!("https://acme.example realm:{}", "ab".repeat(32))).expect("a hint").origins()[0].clone();
        let dial = EndpointDial { member_index: 1, origin: acme.clone(), kind: MemberKind::Https, addresses: Vec::new() };
        let members = vec![MemberOutcome::Dead { origin: acme.clone() }, MemberOutcome::WouldDial { origin: acme, kind: MemberKind::Https, addresses: Vec::new() }];
        let bound = |keys| Resolution::Bound { standing: standing(false), keys, endpoint: endpoint(&["https://dead.example", "https://acme.example"]), dial: dial.clone(), members: members.clone() };
        assert_eq!(surfaced(&bound(None)), None);
        let key = skep_client::sheet::KeyFile::new(skep_client::sheet::Seed::fresh(), false, None, None).public;
        assert_eq!(
            bound_said(&bound(Some(vec![skep_identity::Enrolled { key, anchor: false }])), Some(&a("1.0.1.0.2"))),
            "BOUND: the prefix 1.5 is bound to the account 1.0.2: dial https://acme.example, member 2 of 2 in the org's order; read 1.0.1.0.2 there, the address in that board's local form (REG-1.63); the account's key set holds 1 key as of the registry's head"
        );
        let bare = bound_said(&bound(None), None);
        assert!(bare.contains("; a bare prefix names no place on that board; the account's key set is undeterminable here"), "{bare}");
        assert_eq!((count(1, "row"), count(2, "row")), ("1 row".to_string(), "2 rows".to_string()));
    }
}
