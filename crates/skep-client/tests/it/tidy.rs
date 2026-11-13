//! THE ARRANGEMENT, CHECKED: what `src/ceremony.rs` and `src/person.rs`
//! promise about where code lives, read off the crate's own source.
//!
//! THE CEREMONY'S LAYERS. Every in-crate module a `src/` file names in code
//! — the leading module segments of each `crate::…`, `super::…` and
//! `self::…` path, a brace group's members each read joined to the path
//! before it — keeps `ceremony`'s rule: outside `ceremony/` a file names no
//! ceremony module, the ceremonies standing on top of the crate; inside it a
//! COMPOSITION names no walk, and a WALK names no walk but its own — its
//! child modules (`claim::hosted`, `recover::loss`) naming their parent
//! included. What two walks share is a composition's. Exempt: `ceremony.rs`
//! naming its own children (the tree itself, not an import); comments, doc
//! links included; and tests — a `tests.rs` file, or everything from an
//! inline `mod tests {` on. A module under `ceremony/` in neither row of
//! [`WALKS`] and [`COMPOSITIONS`] fails until it is placed, and placing it
//! is the decision `ARCHITECTURE.md` §The client records.
//!
//! THE SCRIPTED PERSON, GATED: `person::scripted` compiles only under the
//! `test-hooks` feature (or `test`) — the second test below.
//!
//! THE SEARCH HALF, GATED: `search` compiles only under the `search` feature
//! — OFF by default, so the default build exports no feed consumer and
//! `client.md` §1.1's fence holds of it as written — the third test below.
//!
//! THE MERGE, GATED: `merge` compiles only under the `merge` feature — OFF
//! by default, so the default build holds no merge — the fourth test below;
//! and `history`, the restore over the merge's reader, under the same
//! feature — the fifth.
//!
//! THE TEST TRUST ROOT, GATED: the one judge of a server's certificate
//! beside the platform's trust store, `dial.rs`'s `test_root`, compiles only
//! under `tls` and `test-hooks` together, and no manifest turns `test-hooks`
//! on for a build that ships — so no shipped dialer can trust a root the
//! platform does not — the sixth test below.

use std::path::{Path, PathBuf};

/// The walks, one gesture each.
const WALKS: &[&str] = &["accept", "claim", "enroll", "handoff", "recover", "retire", "rotate"];

/// The compositions every walk runs over.
const COMPOSITIONS: &[&str] =
    &["backup", "deposit", "enumerate", "first_session", "handshake", "import", "payload", "preview", "reads", "trail"];

#[test]
fn a_walk_names_no_other_walk_and_a_composition_names_none() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let modules: Vec<String> = files.iter().map(|f| module_of(&src, f)).collect();
    for row in WALKS.iter().chain(COMPOSITIONS) {
        assert!(
            modules.iter().any(|m| *m == format!("ceremony::{row}")),
            "row `{row}` names no module under src/ceremony/: drop it, and its line in ARCHITECTURE.md"
        );
    }
    let mut faults = Vec::new();
    for (file, module) in files.iter().zip(&modules) {
        if file.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let path = file.strip_prefix(&src).unwrap().display().to_string();
        let from = place(module);
        match from {
            Place::Root => continue, // the tree itself
            Place::Under(row) if !WALKS.contains(&row) && !COMPOSITIONS.contains(&row) => {
                faults.push(format!(
                    "src/{path}: `{module}` is in neither row: place it among WALKS or COMPOSITIONS, and in ARCHITECTURE.md"
                ));
                continue;
            }
            _ => {}
        }
        let text = std::fs::read_to_string(file).unwrap();
        let code: Vec<(usize, &str)> = code_lines(&text).collect();
        for (n, named_path) in named_paths(&code) {
            let Some(target) = resolve(module, &named_path) else { continue };
            let at = format!("src/{path}:{n}");
            match (from, place(&target)) {
                (_, Place::Outside) => {}
                (Place::Outside, _) => {
                    faults.push(format!("{at}: `{module}` names `{target}` — nothing outside `ceremony` names it"))
                }
                (Place::Under(own), Place::Under(named)) if named != own && WALKS.contains(&named) => {
                    let who = if WALKS.contains(&own) { "a walk names another walk" } else { "a composition names a walk" };
                    faults.push(format!("{at}: `{module}` names `{target}` — {who}"));
                }
                _ => {}
            }
        }
    }
    assert!(faults.is_empty(), "the ceremony's layers; these lines cross them:\n{}", faults.join("\n"));
}

/// THE SCRIPTED PERSON, GATED: `person::scripted`, the test double of the
/// `Person` seam, compiles only under `test-hooks` (or `test`), gated on its
/// `mod` line in `src/person.rs`. `Cargo.toml`'s `test-hooks` card promises
/// a build that compiles no test compiles none of it; the gate's
/// `--features acting` check proves the library COMPILES without the
/// feature, never that the module is not in it — a dropped gate still
/// compiles, and ships, with every other test green.
#[test]
fn the_scripted_person_compiles_only_under_test_hooks() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(src.join("person/scripted.rs").is_file(), "src/person/scripted.rs: the module this check reads has moved");
    let text = std::fs::read_to_string(src.join("person.rs")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim().ends_with("mod scripted;"))
        .expect("src/person.rs declares `mod scripted;`: the declaration this check reads has moved");
    let gated = lines[..at].iter().rev().take_while(|l| l.trim_start().starts_with("#[")).any(|l| is_gate(l.trim()));
    assert!(gated, "src/person.rs:{}: `{}` compiles without `test-hooks`", at + 1, lines[at].trim());
}

/// THE SEARCH HALF, GATED (`client.md` §1.1, §4e; the `search` feature's
/// card in `Cargo.toml`): `pub mod search;` in `src/lib.rs` is gated on the
/// `search` feature, which the manifest leaves OFF by default, so the
/// default build of the library exports no `search` module — no feed
/// consumer, no content read — and the shell turns it on as it turns `tls`
/// on. The gate's `--no-default-features` and `--features acting` checks
/// prove the library COMPILES without it; this test proves the module is
/// not IN it.
#[test]
fn the_search_module_compiles_only_under_the_search_feature_which_is_off_by_default() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(root.join("src/search.rs").is_file(), "src/search.rs: the module this check reads has moved");
    let text = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim() == "pub mod search;")
        .expect("src/lib.rs declares `pub mod search;`: the declaration this check reads has moved");
    let gate = lines[..at].iter().rev().take_while(|l| l.trim_start().starts_with("#[")).find(|l| l.contains(r#"feature = "search""#) && l.trim().starts_with("#[cfg(") && !l.contains("not("));
    assert!(gate.is_some(), "src/lib.rs:{}: `pub mod search;` compiles without the `search` feature", at + 1);
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let default = manifest.lines().find(|l| l.trim_start().starts_with("default =")).expect("a `default` feature line");
    assert!(!default.contains("search"), "Cargo.toml: `search` is on by default: {default}");
    assert!(manifest.lines().any(|l| l.trim_start().starts_with("search = [") && l.contains("\"acting\"") && l.contains("dep:skep-search")), "Cargo.toml: the `search` feature implies `acting` and turns the optional skep-search on");
    let search_dep = manifest.lines().find(|l| l.trim_start().starts_with("skep-search = {") && l.contains("optional = true")).expect("skep-search is an OPTIONAL normal dependency");
    let _ = search_dep;
}

/// THE MERGE, GATED (the design's merge record §7; the `merge` feature's
/// card in `Cargo.toml`): `pub mod merge;` in `src/lib.rs` is gated on the
/// `merge` feature, which the manifest leaves OFF by default and which
/// implies `acting`, so the default build of the library exports no `merge`
/// module — no composition, no gap report — and the editor's shell turns it
/// on as it turns `search` on. The gate's `--no-default-features` and
/// `--features acting` checks prove the library COMPILES without it; this
/// test proves the module is not IN it.
#[test]
fn the_merge_module_compiles_only_under_the_merge_feature_which_is_off_by_default() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(root.join("src/merge.rs").is_file(), "src/merge.rs: the module this check reads has moved");
    let text = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim() == "pub mod merge;")
        .expect("src/lib.rs declares `pub mod merge;`: the declaration this check reads has moved");
    let gate = lines[..at].iter().rev().take_while(|l| l.trim_start().starts_with("#[")).find(|l| l.contains(r#"feature = "merge""#) && l.trim().starts_with("#[cfg(") && !l.contains("not("));
    assert!(gate.is_some(), "src/lib.rs:{}: `pub mod merge;` compiles without the `merge` feature", at + 1);
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let default = manifest.lines().find(|l| l.trim_start().starts_with("default =")).expect("a `default` feature line");
    assert!(!default.contains("merge"), "Cargo.toml: `merge` is on by default: {default}");
    assert!(manifest.lines().any(|l| l.trim_start().starts_with("merge = [") && l.contains("\"acting\"")), "Cargo.toml: the `merge` feature implies `acting`");
}

/// THE RESTORE, GATED WITH THE MERGE (`client.md` §4b.1's `history.restore`
/// row; B3-S7): `pub mod history;` in `src/lib.rs` is gated on the `merge`
/// feature, whose reader and one write it rides, so the default build of the
/// library exports no restore either.
#[test]
fn the_history_module_compiles_only_under_the_merge_feature() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(root.join("src/history.rs").is_file(), "src/history.rs: the module this check reads has moved");
    let text = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim() == "pub mod history;")
        .expect("src/lib.rs declares `pub mod history;`: the declaration this check reads has moved");
    let gate = lines[..at].iter().rev().take_while(|l| l.trim_start().starts_with("#[")).find(|l| l.contains(r#"feature = "merge""#) && l.trim().starts_with("#[cfg(") && !l.contains("not("));
    assert!(gate.is_some(), "src/lib.rs:{}: `pub mod history;` compiles without the `merge` feature", at + 1);
}

/// Checks that no shipped build can trust a root the platform does not.
///
/// The dialer judges a server's certificate by the platform's trust store.
/// The one other judge is the test trust root, `dial.rs`'s `test_root`
/// module inside its `tls` arm: a suite hands a dialer one certificate and
/// that dialer trusts it alone. This holds the seam to `test-hooks`
/// (SP-28), in four parts.
///
/// 1. The module is gated on its `mod` line, inside the `tls`-gated arm.
/// 2. Every code line of `src/dial.rs` outside the module that names it —
///    the field that holds a root, that field's one initializer, the
///    handshake's choice of judge — stands directly under a gate: on
///    `test-hooks` inside the arm, on `tls` and `test-hooks` together
///    outside it.
/// 3. No code line under `src/` outside the module names a root store or a
///    certificate verifier of the crate's own: the platform's verifier is
///    reached through `rustls-platform-verifier` alone.
/// 4. `Cargo.toml` leaves `test-hooks` off by default and lets no other
///    feature turn it on, and every workspace manifest that names
///    `skep-client` with `test-hooks` does so under `[dev-dependencies]`,
///    which a build that compiles no test never reads.
///
/// The gate's `--features` checks prove the library and the `skep` binary
/// compile without the seam; this proves the seam is not in them. Each part
/// asserts it found the lines it reads (SP-29).
#[test]
fn the_test_trust_root_compiles_only_under_tls_and_test_hooks() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/dial.rs")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let attributes_above = |at: usize| lines[..at].iter().rev().take_while(|l| l.trim_start().starts_with("#[")).map(|l| l.trim()).collect::<Vec<_>>();
    let on_test_hooks = |a: &str| a == r#"#[cfg(feature = "test-hooks")]"# || a == r#"#[cfg(all(feature = "tls", feature = "test-hooks"))]"#;
    let on_both = |a: &str| a == r#"#[cfg(all(feature = "tls", feature = "test-hooks"))]"#;

    // 1 — the arm, and the module inside it.
    let arm = lines
        .iter()
        .position(|l| *l == "mod tls {")
        .filter(|at| attributes_above(*at) == [r#"#[cfg(feature = "tls")]"#])
        .expect("src/dial.rs opens its `tls` arm with `#[cfg(feature = \"tls\")] mod tls {`: the arm this check reads has moved");
    let arm_end = arm + lines[arm..].iter().position(|l| *l == "}").expect("the `tls` arm closes");
    let module = lines
        .iter()
        .position(|l| l.trim().ends_with("mod test_root {"))
        .expect("src/dial.rs declares `mod test_root {`: the module this check reads has moved");
    let indent = &lines[module][..lines[module].len() - lines[module].trim_start().len()];
    let module_end = module + lines[module..].iter().position(|l| *l == format!("{indent}}}")).expect("the `test_root` module closes");
    assert!(arm < module && module_end < arm_end, "src/dial.rs:{}: `mod test_root` stands outside the `tls` arm", module + 1);
    assert!(
        attributes_above(module).iter().any(|a| on_test_hooks(a)),
        "src/dial.rs:{}: `{}` compiles without `test-hooks`",
        module + 1,
        lines[module].trim()
    );

    // 2 — the lines outside the module that name it.
    let names_the_seam = |l: &str| ["test_root", "TestRoot"].iter().any(|name| l.contains(name));
    let mut outside = 0;
    for (n, line) in code_lines(&text).filter(|(n, _)| !(module + 1..=module_end + 1).contains(n)) {
        if !names_the_seam(line) {
            continue;
        }
        outside += 1;
        let in_the_arm = (arm + 1..=arm_end + 1).contains(&n);
        let gated = attributes_above(n - 1).iter().any(|a| if in_the_arm { on_test_hooks(a) } else { on_both(a) });
        assert!(gated, "src/dial.rs:{n}: `{}` names the test trust root and compiles without `test-hooks`", line.trim());
    }
    assert_eq!(outside, 3, "src/dial.rs names the test trust root outside its module on {outside} lines: the field, its one initializer and the handshake's choice are the three this check knows");

    // 3 — no root store and no verifier of the crate's own, anywhere else.
    let judges = ["RootCertStore", "with_root_certificates", "dangerous()", "with_custom_certificate_verifier", "ServerCertVerifier", "new_with_extra_roots", "add_parsable_certificates"];
    assert!(
        lines[module..=module_end].iter().any(|l| l.contains("RootCertStore")),
        "the `test_root` module no longer builds its root store: the names this check refuses elsewhere have moved"
    );
    let src = root.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut faults = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap();
        let is_dial = file == &src.join("dial.rs");
        for (n, line) in code_lines(&source) {
            if is_dial && (module + 1..=module_end + 1).contains(&n) {
                continue;
            }
            if let Some(judge) = judges.iter().find(|judge| line.contains(**judge)) {
                faults.push(format!("{}:{n}: `{judge}`", file.strip_prefix(root).unwrap().display()));
            }
        }
    }
    assert!(faults.is_empty(), "a certificate's judge beside the platform's, outside the test trust root:\n{}", faults.join("\n"));

    // 4 — the manifests.
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let feature_lines: Vec<&str> = manifest
        .lines()
        .skip_while(|l| l.trim() != "[features]")
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.trim_start().starts_with('#') && l.contains(" = ["))
        .collect();
    assert!(feature_lines.iter().any(|l| l.starts_with("test-hooks = [")), "Cargo.toml no longer declares `test-hooks`");
    assert!(feature_lines.iter().any(|l| l.starts_with("default = [")), "Cargo.toml no longer declares `default`");
    for line in &feature_lines {
        assert!(
            line.starts_with("test-hooks = [") || !line.contains("test-hooks"),
            "Cargo.toml: a feature other than `test-hooks` turns it on: {line}"
        );
    }
    let crates = root.parent().expect("the workspace's crates directory");
    let (mut dev_lines, mut shipped) = (0, Vec::new());
    for entry in std::fs::read_dir(crates).unwrap() {
        let path = entry.unwrap().path().join("Cargo.toml");
        let Ok(manifest) = std::fs::read_to_string(&path) else { continue };
        let mut table = "";
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                table = line;
            } else if !line.starts_with('#') && line.contains("skep-client") && line.contains("test-hooks") {
                if table == "[dev-dependencies]" {
                    dev_lines += 1;
                } else {
                    shipped.push(format!("{} {table}: {line}", path.strip_prefix(crates).unwrap().display()));
                }
            }
        }
    }
    assert!(dev_lines >= 2, "{dev_lines} `[dev-dependencies]` lines name `skep-client` with `test-hooks`: this crate's own and a suite's are the least this check reads");
    assert!(shipped.is_empty(), "a build that ships turns `skep-client`'s `test-hooks` on:\n{}", shipped.join("\n"));
}

/// Where a module stands against the ceremony.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place<'a> {
    /// Outside `ceremony`.
    Outside,
    /// `ceremony` itself.
    Root,
    /// Under `ceremony`, in the subtree of this child.
    Under(&'a str),
}

fn place(module: &str) -> Place<'_> {
    match module.strip_prefix("ceremony") {
        Some("") => Place::Root,
        Some(rest) => match rest.strip_prefix("::") {
            Some(rest) => Place::Under(rest.split("::").next().unwrap_or(rest)),
            None => Place::Outside,
        },
        None => Place::Outside,
    }
}

/// One path as written in `module`, resolved to the in-crate module it
/// names: `crate::` starts at the root, `self::` at `module`, each `super::`
/// one step up; the leading lowercase segments after that name the module.
/// A lowercase item riding along (`ceremony::payload::payload_text`) is
/// harmless — a place reads the first segments alone. `None` for a path
/// outside this crate.
fn resolve(module: &str, named_path: &str) -> Option<String> {
    let mut segments = named_path.split("::").filter(|s| !s.is_empty()).peekable();
    let mut base: Vec<&str> = match segments.next() {
        Some("crate") => Vec::new(),
        Some("self") => module.split("::").collect(),
        Some("super") => {
            let mut up: Vec<&str> = module.split("::").collect();
            up.pop();
            up
        }
        _ => return None,
    };
    while segments.peek() == Some(&"super") {
        segments.next();
        base.pop();
    }
    base.extend(segments.take_while(|s| s.starts_with(|c: char| c.is_ascii_lowercase())));
    Some(base.join("::"))
}

/// Every in-crate path the code names, with the line it starts on: each
/// `crate::…`, `super::…` and `self::…` token — a maximal run of identifier
/// characters and `:` — and, where one ends at a brace group (`use
/// crate::ceremony::{deposit::DepositKind, claim::hosted};`, on one line or across
/// several), each member of the group joined to it, a nested group's
/// likewise. The token alone is not enough there: `crate::` names no module
/// and `super::` only the parent, so a group would hide every module its
/// members name.
fn named_paths(code: &[(usize, &str)]) -> Vec<(usize, String)> {
    // One text, and each byte's line, so a group may span lines.
    let mut text = String::new();
    let mut line_of = Vec::new();
    for &(n, line) in code {
        text.push_str(line);
        text.push('\n');
        line_of.resize(text.len(), n);
    }
    let is_path = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b':';
    let bytes = text.as_bytes();
    let mut paths = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_path(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_path(bytes[i]) {
            i += 1;
        }
        let token = &text[start..i];
        if !["crate::", "super::", "self::"].iter().any(|root| token.starts_with(root)) {
            continue;
        }
        let after = text[i..].trim_start();
        if token.ends_with("::") && after.starts_with('{') {
            let (members, end) = brace_group(&text, text.len() - after.len());
            paths.extend(members.into_iter().map(|m| (line_of[start], format!("{token}{m}"))));
            i = end;
        } else {
            paths.push((line_of[start], token.to_string()));
        }
    }
    paths
}

/// The members of the brace group whose `{` is at byte `open` of `text`, each
/// expanded to a path ([`expand_member`]), and the byte just past its `}`.
fn brace_group(text: &str, open: usize) -> (Vec<String>, usize) {
    let mut depth = 0;
    let mut close = text.len();
    for (j, b) in text.bytes().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = j;
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = &text[open + 1..close];
    let (mut members, mut depth, mut from) = (Vec::new(), 0, 0);
    for (j, c) in inner.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                members.extend(expand_member(&inner[from..j]));
                from = j + 1;
            }
            _ => {}
        }
    }
    members.extend(expand_member(&inner[from..]));
    (members, (close + 1).min(text.len()))
}

/// One member of a brace group as the paths it names: `a::b` itself, `a::{b,
/// c}` as `a::b` and `a::c`, `x as y` as `x`, and an empty member — a
/// trailing comma — as none.
fn expand_member(member: &str) -> Vec<String> {
    let member = member.trim();
    match member.find('{') {
        Some(k) => {
            let prefix = member[..k].trim_end();
            brace_group(member, k).0.into_iter().map(|m| format!("{prefix}{m}")).collect()
        }
        None => match member.split(" as ").next().unwrap_or("").trim() {
            "" => Vec::new(),
            path => vec![path.to_string()],
        },
    }
}

/// A `cfg` attribute that confines what it gates to test builds: the
/// `test-hooks` feature, or `test` itself.
fn is_gate(attribute: &str) -> bool {
    attribute.starts_with("#[cfg(")
        && !attribute.contains("not(")
        && (attribute.contains(r#"feature = "test-hooks""#) || attribute == "#[cfg(test)]")
}

/// A file's code lines, numbered from 1: comment lines dropped (a doc link
/// is no import), a trailing ` //` comment cut, and nothing from an inline
/// `mod tests {` on.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .take_while(|(_, line)| line.trim() != "mod tests {")
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(i, line)| (i + 1, line.split(" //").next().unwrap_or(line)))
}

/// `src/ceremony/claim/hosted.rs` → `ceremony::claim::hosted`;
/// `src/ceremony.rs` → `ceremony`.
fn module_of(src: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(src).unwrap().with_extension("");
    let mut segments: Vec<String> = relative.iter().map(|s| s.to_string_lossy().into_owned()).collect();
    if segments.len() > 1 && segments.last().is_some_and(|s| s == "mod") {
        segments.pop();
    }
    segments.join("::")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}
