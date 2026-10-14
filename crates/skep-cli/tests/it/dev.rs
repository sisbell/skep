//! THE DEV BINARY's FENCE: `skep-dev seed` driven through argv against a
//! board the suite spawns in-process and claims as `cli.rs`'s boards are
//! claimed (the scripted person behind `test-hooks`, the SUITE's
//! dev-dependency, never the tool's), over a CORPUS the suite builds under
//! the system temp dir — a git repository of a few `.md` files with cites
//! among them (one with a section, one to a file outside the set, one file
//! holding a `## 1.2` heading), `git init`, one commit — at `--documents 12
//! --versions 4 --drafts 3`, so the three version arms, the window, the
//! ghost and the second account all land on one small board.
//!
//! F1 a guest reads every edition byte-exact; F2 every link resolves at both
//! ends — the type, the cite's span, the cited edition — the sectioned cite
//! lands on the document holding the section, and the ghost answers
//! `doc_not_registered`; F3 the versions differ exactly as each rotated arm
//! says, `compare` answers the predicted pairs, the bare address floats, and
//! the removed arm's link floats; F4 the drafts answer the claimant and are
//! withheld from a guest, the windowed run is withheld to the width and read
//! by the claimant, and the second account's draft is withheld from the
//! claimant too; F5 a second run adds nothing and says so, and a run cut
//! short at its fifth document resumes and lands what a one-shot run lands;
//! F8 an unclaimed board and a stranger's board halt before any write, and
//! the agent space holds no document after a run. F6, the `--bin skep` build
//! yielding one binary, is the gate's and the lane's by hand; F7 the budgets
//! suite's; F9 `tidy`'s.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use skep_client::board::{frames, Answer, Board, Opened, SessionBody, Token};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_corpus::{Corpus, Cut};
use skepd::{embed, AuthOptions, MediaOptions, Skepd, DEFAULT_WORKERS};
use tempfile::TempDir;

use crate::common::{origin, s, spawn, Run};

/// The citation type every link is typed, as the tool spells it.
const CITATION_TYPE: &str = "1.1.0.1.0.1.0.3.13";

/// The suite's counts: twelve editions, a version every fourth document
/// (documents 1, 5 and 9 — the three arms; `--versions 4` in
/// [`seed_args`]), three drafts.
const DOCUMENTS: usize = 12;
const DRAFTS: usize = 3;

/// The sentence the changed arm writes, as the tool spells it.
const CHANGED: &str = "This sentence stands changed in the second version.";

// ── THE CORPUS ─────────────────────────────────────────────────────────────

/// One paragraph of deterministic prose, about 450 bytes, with `cite` set
/// in its middle sentence where one is given.
fn paragraph(file: &str, i: usize, cite: Option<&str>) -> String {
    let mut p = format!("Paragraph {i} of {file} opens here.");
    let fill = [
        " The board holds prose for the page to read.",
        " A guest meets every edition as published.",
        " The claimant alone reads a draft.",
    ];
    let mut k = 0;
    while p.len() < 200 {
        p.push_str(fill[k % 3]);
        k += 1;
    }
    if let Some(c) = cite {
        p.push_str(&format!(" See `{c}` for the words this paragraph leans on."));
    }
    while p.len() < 450 {
        p.push_str(fill[k % 3]);
        k += 1;
    }
    p
}

/// A file of `n` paragraphs, `cite_at(i)` naming the cite paragraph `i`
/// carries, and `heading_at` the index that is the `## 1.2` heading.
fn prose(
    file: &str,
    n: usize,
    cite_at: impl Fn(usize) -> Option<&'static str>,
    heading_at: Option<usize>,
) -> String {
    (0..n)
        .map(|i| {
            if heading_at == Some(i) {
                "## 1.2 The second section".to_string()
            } else {
                paragraph(file, i, cite_at(i))
            }
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// The suite's corpus: README with a cite into the set and one to a file
/// that does not exist; `a.md` with the `## 1.2` heading and cites by
/// basename, by path and by section into itself; `b.md` citing the section
/// and the outside name; `ux/c.md`, long enough for the drafts; a bundle
/// and an image the tier excludes.
fn corpus_files() -> Vec<(&'static str, String)> {
    vec![
        (
            "README.md",
            prose(
                "README",
                4,
                |i| match i {
                    0 => Some("_designs/a.md"),
                    2 => Some("nowhere.md"),
                    _ => None,
                },
                None,
            ),
        ),
        (
            "_designs/a.md",
            prose(
                "a",
                40,
                |i| {
                    if i == 10 {
                        Some("a.md §1.2")
                    } else if i % 3 == 1 {
                        Some("b.md")
                    } else if i % 5 == 2 {
                        Some("README.md")
                    } else {
                        None
                    }
                },
                Some(30),
            ),
        ),
        (
            "_designs/b.md",
            prose(
                "b",
                40,
                |i| {
                    if i == 20 {
                        Some("nowhere.md")
                    } else if i % 3 == 1 {
                        Some("a.md §1.2")
                    } else if i % 4 == 2 {
                        Some("_designs/a.md")
                    } else {
                        None
                    }
                },
                None,
            ),
        ),
        ("_context.all.md", "an excluded bundle".to_string()),
        (
            "ux/c.md",
            prose(
                "c",
                120,
                |i| {
                    if i % 3 == 1 {
                        Some("b.md")
                    } else if i % 7 == 3 {
                        Some("README.md")
                    } else {
                        None
                    }
                },
                None,
            ),
        ),
    ]
}

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.name=skep",
            "-c",
            "user.email=skep@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The corpus committed under `dir/repo`: the repository's path, the
/// commit, and the cut the tool will make of it.
fn repository(dir: &Path) -> (PathBuf, String, Cut) {
    let repo = dir.join("repo");
    for (path, text) in corpus_files() {
        let at = repo.join(path);
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(&at, text).unwrap();
    }
    std::fs::write(repo.join("ux/shot.PNG"), [0x89, b'P', b'N', b'G']).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "the corpus"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    let cut = Corpus::open(&repo, &head)
        .unwrap()
        .cut_sourced(DOCUMENTS + DRAFTS + 1)
        .expect("the corpus holds the shapes");
    (repo, head, cut)
}

// ── THE BOARD ──────────────────────────────────────────────────────────────

/// A claimed board through the LIBRARY, as `ceremonies.rs` claims one: the
/// store holds the device key and the account's line.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions {
        principal: None,
        display_name: Some("a name".into()),
        anchor_out: vec![anchors.join("a"), anchors.join("b")],
        paper: false,
        host_name: "testhost".into(),
        date: "2026-10-10".into(),
    };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts)
        .unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")))
    else {
        panic!("a stranger's board")
    };
}

/// The built `skep-dev` with `args`, every `SKEP_*` variable and `HOME`
/// scrubbed, stdin closed, stdout and stderr piped.
fn dev_command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-dev"));
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for var in [
        "SKEP_BOARD",
        "SKEP_KEYSTORE",
        "SKEP_KEY",
        "SKEP_PRINCIPAL",
        "SKEP_SESSION",
        "SKEP_SEARCH_CORPUS",
        "HOME",
        "USERPROFILE",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// The built `skep-dev` run with `args` ([`dev_command`]).
fn skep_dev(args: &[&str]) -> Run {
    let out = dev_command(args).output().expect("spawn skep-dev");
    Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).to_string(),
        err: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// [`skep_dev`], its stderr read as the run says it: `release` is called the
/// moment a line holding `needle` is said — or at the run's end where none
/// is — so a test holds the board in a state until the run is seen to meet
/// it, and never past the run.
fn skep_dev_releasing(args: &[&str], needle: &str, release: impl FnOnce()) -> Run {
    let mut child = dev_command(args).spawn().expect("spawn skep-dev");
    let mut stdout = child.stdout.take().expect("stdout piped");
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let mut release = Some(release);
    let mut reader = BufReader::new(child.stderr.take().expect("stderr piped"));
    let (mut err, mut line) = (String::new(), String::new());
    while let Ok(n @ 1..) = reader.read_line(&mut line) {
        let _ = n;
        if line.contains(needle) {
            if let Some(release) = release.take() {
                release();
            }
        }
        err.push_str(&line);
        line.clear();
    }
    if let Some(release) = release.take() {
        release();
    }
    let status = child.wait().expect("wait");
    Run { code: status.code().unwrap_or(-1), out: out.join().expect("stdout read"), err }
}

/// `seed`'s argv against `board` from `store` over `repo` at `pin`.
fn seed_args<'a>(board: &'a str, store: &'a str, repo: &'a str, pin: &'a str) -> Vec<&'a str> {
    vec![
        "seed",
        "--board",
        board,
        "--dir",
        store,
        "--repo",
        repo,
        "--pin",
        pin,
        "--documents",
        "12",
        "--versions",
        "4",
        "--drafts",
        "3",
    ]
}

fn board_at(origin: &str) -> Board {
    Board::new(Origin::parse(origin).unwrap(), PlainHttp::new())
}

fn bare(board: &Board, principal: u64) -> Token {
    match board.session_open(SessionBody::Bare { principal }).expect("bare session") {
        Opened::Token(t) => t,
        other => panic!("the bare bind answered {other:?}"),
    }
}

fn guest(board: &Board, frame: &Value) -> Value {
    board.guest(frame).expect("the exchange")
}

fn under(board: &Board, token: &Token, frame: &Value) -> Value {
    match board.op(Some(token), frame).expect("the exchange") {
        Answer::Document(v) => v,
        Answer::Closed => panic!("closed"),
    }
}

fn log_position(board: &Board) -> u64 {
    board.health().expect("health").log_position()
}

/// One item of a delivery: text, or a withheld run.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Text(Vec<u8>),
    Withheld { width: u64, origin: String },
}

/// A `delivery`'s items.
fn items(v: &Value) -> Vec<Item> {
    assert_eq!(v["resp"].as_str(), Some("delivery"), "{v}");
    v["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            if let Some(text) = item["content"].as_str() {
                Item::Text(text.as_bytes().to_vec())
            } else if let Some(h) = item["hex"].as_str() {
                Item::Text(
                    (0..h.len() / 2)
                        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
                        .collect(),
                )
            } else if let Some(w) = item.get("withheld") {
                Item::Withheld {
                    width: w["width"].as_str().unwrap().parse().unwrap(),
                    origin: w["origin"].as_str().unwrap().to_string(),
                }
            } else {
                panic!("an item of another kind: {item}")
            }
        })
        .collect()
}

/// The bytes of a delivery holding text alone.
fn text_of(v: &Value) -> Vec<u8> {
    items(v)
        .into_iter()
        .flat_map(|i| match i {
            Item::Text(b) => b,
            other => panic!("not text: {other:?}"),
        })
        .collect()
}

/// The content extent `retrieve_doc_v_span_set` answers for `doc`.
fn extent(board: &Board, doc: &str) -> u64 {
    let v = guest(board, &frames::span_set(doc));
    assert_eq!(v["resp"].as_str(), Some("span_set"), "{v}");
    v["set"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["start"].as_str() == Some("1.1"))
        .map(|s| s["width"].as_str().unwrap().strip_prefix("0.").unwrap().parse().unwrap())
        .unwrap_or(0)
}

/// `retrieve_v` over the whole extent of `doc`, token-free.
fn read_guest(board: &Board, doc: &str) -> Value {
    let n = extent(board, doc);
    guest(board, &frames::retrieve_v(doc, 1, n.max(1)))
}

/// `retrieve_v` over the whole extent of `doc` under `token`.
fn read_as(board: &Board, token: &Token, doc: &str) -> Value {
    let n = extent(board, doc);
    under(board, token, &frames::retrieve_v(doc, 1, n.max(1)))
}

/// The `rejected` document's code, where the answer is one.
fn rejected(v: &Value) -> Option<&str> {
    (v["resp"].as_str() == Some("rejected")).then(|| v["code"].as_str()).flatten()
}

/// The cites of `bytes` as the tool finds them: a backticked token on one
/// line whose first word ends in `.md`, alone or with `§` and a section —
/// `(offset inside the ticks, length, path, section)`.
fn cites(bytes: &[u8]) -> Vec<(usize, usize, String, Option<String>)> {
    let text = std::str::from_utf8(bytes).unwrap();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = text[i..].find('`') {
        let open = i + rel;
        let Some(rel_close) = text[open + 1..].find(['`', '\n']) else { break };
        let close = open + 1 + rel_close;
        i = close + 1;
        if &text[close..=close] == "\n" {
            continue;
        }
        let token = &text[open + 1..close];
        let (path, rest) = token.split_once(' ').map_or((token, ""), |(p, r)| (p, r.trim()));
        if !path.ends_with(".md") || path.len() <= 3 {
            continue;
        }
        let section = if rest.is_empty() {
            None
        } else {
            rest.strip_prefix('§').map(|s| s.trim().to_string())
        };
        if !rest.is_empty() && section.is_none() {
            continue;
        }
        out.push((open + 1, token.len(), path.to_string(), section));
    }
    out
}

/// The manifest's lines whose id ends in `:link:<n>`, in order.
fn manifest_links(path: &str) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("the manifest")
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str::<Value>(l).expect("a JSON line"))
        .filter(|v| v["id"].as_str().is_some_and(|id| id.contains(":link:")))
        .collect()
}

fn manifest_item(path: &str, id: &str) -> Value {
    std::fs::read_to_string(path)
        .expect("the manifest")
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str::<Value>(l).expect("a JSON line"))
        .find(|v| v["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("no `{id}` in the manifest"))
}

/// The members of a seed's JSON that name what landed — equal across a
/// one-shot run, its idempotent second run and a resumed run.
fn shape(v: &Value) -> Value {
    serde_json::json!({
        "staging": v["staging"], "editions": v["editions"], "links": v["links"], "versions": v["versions"],
        "drafts": v["drafts"], "window": v["window"], "second_account": v["second_account"], "corpus": v["corpus"],
        "account": v["account"], "principal": v["principal"],
    })
}

/// The expected shape of the suite's seed on a fresh board: doc 1 at
/// `1.0.1.0.1`, the staging draft `.2`, the editions `.3` to `.14`, the
/// drafts `.15` to `.17`, the second account `1.0.2`.
fn assert_expected_shape(v: &Value, cut: &Cut) {
    assert_eq!(v["tool"], "skep-dev seed");
    assert_eq!(v["account"], "1.0.1");
    assert_eq!(v["principal"], 1);
    assert_eq!(v["staging"]["drafts"], serde_json::json!(["1.0.1.0.2"]));
    assert_eq!(v["editions"]["count"], 12);
    assert_eq!(v["editions"]["first"], "1.0.1.0.3");
    assert_eq!(v["editions"]["last"], "1.0.1.0.14");
    assert_eq!(v["editions"]["members"], 15);
    let planted: usize =
        cut.documents.iter().take(DOCUMENTS).map(|s| cites(&s.document.bytes).len()).sum();
    let outside: usize = cut
        .documents
        .iter()
        .take(DOCUMENTS)
        .map(|s| cites(&s.document.bytes).iter().filter(|c| c.2 == "nowhere.md").count())
        .sum();
    assert!(
        planted > 10 && outside >= 2,
        "the corpus plants cites: {planted} in the set, {outside} outside"
    );
    assert_eq!(
        v["links"]["count"], planted,
        "every cite inside the set lands, duplicates included"
    );
    assert_eq!(v["links"]["type"], CITATION_TYPE);
    assert_eq!(v["links"]["outside"]["rule"], "ghost");
    assert_eq!(v["links"]["outside"]["count"], outside);
    assert_eq!(
        v["links"]["outside"]["ghosts"].as_object().unwrap().len(),
        1,
        "one ghost per distinct outside name"
    );
    assert_eq!(
        v["links"]["first"], "1.0.1.0.3.0.2.1",
        "the first link is homed in the first edition's link subspace"
    );
    assert_eq!(v["versions"]["count"], 3);
    assert_eq!(v["versions"]["rule"], "every 4th");
    assert_eq!(
        v["versions"]["members"],
        serde_json::json!(["1.0.1.0.3.2", "1.0.1.0.7.2", "1.0.1.0.11.2"])
    );
    assert_eq!(v["versions"]["arms"], serde_json::json!(["appended", "removed", "changed"]));
    assert_eq!(
        v["drafts"]["addresses"],
        serde_json::json!(["1.0.1.0.15", "1.0.1.0.16", "1.0.1.0.17"])
    );
    assert_eq!(
        v["window"],
        serde_json::json!({"edition": "1.0.1.0.3", "member": "1.0.1.0.3.2", "draft": "1.0.1.0.15", "width": 240})
    );
    assert_eq!(
        v["second_account"],
        serde_json::json!({"account": "1.0.2", "principal": 2, "home": "1.0.2.0.1", "draft": "1.0.2.0.2"})
    );
    assert_eq!(v["corpus"]["cut"], "cut-v1");
    assert_eq!(v["corpus"]["documents"], 12);
    assert_eq!(
        v["corpus"]["bytes"],
        cut.documents.iter().take(DOCUMENTS).map(|s| s.document.bytes.len() as u64).sum::<u64>()
    );
}

fn parse_json(run: &Run) -> Value {
    assert_eq!(run.code, 0, "{run:?}");
    let lines: Vec<&str> = run.out.lines().collect();
    assert_eq!(lines.len(), 1, "one JSON object on stdout: {}", run.out);
    serde_json::from_str(lines[0]).unwrap_or_else(|e| panic!("{e}: {}", run.out))
}

// ── THE FENCE ──────────────────────────────────────────────────────────────

/// F8's refusals ahead of the seed, then the seed and F1–F5 over it.
#[test]
fn the_seed_lands_every_shape_and_a_guest_reads_them() {
    let dir: TempDir = tempfile::tempdir().unwrap();
    let (repo, pin, cut) = repository(dir.path());
    let sd = spawn(&dir.path().join("board"), true);
    let board_origin = origin(sd.port());
    let board = board_at(&board_origin);
    let store = dir.path().join("store");
    let args = seed_args(&board_origin, s(&store), s(&repo), &pin);

    // F8: an UNCLAIMED board halts before any write, the face naming the act.
    let before = log_position(&board);
    let r = skep_dev(&args);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("claim first") && r.err.contains("`skep claim --board"), "{}", r.err);
    assert!(r.out.is_empty(), "a halt carries no data: {}", r.out);
    assert_eq!(log_position(&board), before, "nothing was written");

    claim_board(&board_origin, &store, &dir.path().join("anchors"));

    // F8: a STRANGER's store — a key, no binding — halts before any write.
    let stranger = dir.path().join("stranger");
    FileStore::open(&stranger).generate(Some(Label::new("other").unwrap())).unwrap();
    let before = log_position(&board);
    let mut stranger_args = seed_args(&board_origin, s(&stranger), s(&repo), &pin);
    stranger_args.extend(["--principal", "1"]);
    let r = skep_dev(&stranger_args);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("claimed by 1.0.1; no key in this store is bound to it"), "{}", r.err);
    assert_eq!(log_position(&board), before, "nothing was written");

    // THE SEED — its object printed, so a `--no-capture` run shows it whole —
    // against a board whose write permits the suite holds until the seed says
    // its first `write_busy`: said once as it is met, retried, and counted.
    let before = log_position(&board);
    let permits: Vec<_> = std::iter::from_fn(|| sd.daemon().try_hold_write_permit()).collect();
    assert!(!permits.is_empty(), "the suite holds the board's write permits");
    let busy = "the board answered `write_busy`: each write is retried for up to 60 s, and the retries are counted at the end";
    let r = skep_dev_releasing(&args, busy, || drop(permits));
    println!("skep-dev seed answered: {}", r.out.trim_end());
    let v = parse_json(&r);
    assert_expected_shape(&v, &cut);
    assert_eq!(v["already_seeded"], false);
    assert_eq!(r.err.matches(busy).count(), 1, "the first `write_busy` said once: {}", r.err);
    assert!(
        v["retries"]["write_busy"].as_u64().is_some_and(|n| n >= 1),
        "the retries counted: {v}"
    );
    assert_eq!(v["positions"]["before"], before);
    assert!(v["positions"]["after"].as_u64().unwrap() > before);
    assert!(r.err.contains("mode CLAIMED-PERMISSIVE"), "{}", r.err);
    assert!(r.err.contains("this board now holds"), "the reopen warning: {}", r.err);
    assert!(
        r.err.contains(
            "a new seed of this board; each write is recorded there after the board's ack"
        ),
        "the manifest's line: {}",
        r.err
    );
    // Each phase said as it ends — the editions' last progress line among
    // them, though twelve is no hundred.
    let links_line = format!(
        "links: {} in all, {} of them naming files outside the set (ghosts: 1)",
        v["links"]["count"], v["links"]["outside"]["count"]
    );
    for phase in [
        "editions: 12 of 12 landed",
        links_line.as_str(),
        "versions: 3 in all, the window — 240 positions of 1.0.1.0.15 — in 1.0.1.0.3.2",
        "drafts: 3 in all",
        "second account: 1.0.2, principal 2, its home 1.0.2.0.1 and one draft 1.0.2.0.2",
    ] {
        assert!(r.err.contains(phase), "the phase's line `{phase}`: {}", r.err);
    }
    let manifest = v["manifest"].as_str().unwrap().to_string();
    assert!(
        manifest.ends_with(&format!(
            "store-seed/{}.jsonl",
            board
                .board_term()
                .unwrap()
                .unwrap()
                .chain
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )),
        "{manifest}"
    );
    let claimant = bare(&board, 1);

    // F1: a guest reads every edition byte-exact — the birth member where
    // the document has a second version, the bare address else.
    let editions: Vec<String> = (0..DOCUMENTS).map(|i| format!("1.0.1.0.{}", i + 3)).collect();
    let versioned = [0usize, 4, 8];
    for (i, e) in editions.iter().enumerate() {
        let want = &cut.documents[i].document.bytes;
        let addr = if versioned.contains(&i) { format!("{e}.1") } else { e.clone() };
        assert_eq!(extent(&board, &addr) as usize, want.len(), "{addr}");
        assert_eq!(text_of(&read_guest(&board, &addr)), *want, "{addr} byte-exact for a guest");
    }

    // F2: every link resolves at both ends.
    let links = manifest_links(&manifest);
    assert_eq!(links.len(), v["links"]["count"].as_u64().unwrap() as usize);
    let ghost =
        v["links"]["outside"]["ghosts"]["nowhere.md"].as_str().expect("the ghost").to_string();
    assert!(
        ghost.starts_with("1.0.1.0.")
            && ghost.rsplit('.').next().unwrap().parse::<u64>().unwrap() > 1_000_000,
        "a ghost past the account's last mint: {ghost}"
    );
    let section_document = cut
        .documents
        .iter()
        .take(DOCUMENTS)
        .position(|s| {
            s.paragraphs.iter().any(|p| {
                p.file == "_designs/a.md" && p.heading.as_deref() == Some("1.2 The second section")
            })
        })
        .expect("the heading is in the cut");
    let first_of_a = cut
        .documents
        .iter()
        .take(DOCUMENTS)
        .position(|s| s.paragraphs.iter().any(|p| p.file == "_designs/a.md"))
        .unwrap();
    assert_ne!(section_document, first_of_a, "the section's document is not the file's first");
    let (mut sectioned, mut ghosts) = (0, 0);
    for link in &links {
        let a = link["addr"].as_str().unwrap();
        let home = link["home"].as_str().unwrap();
        let to = link["to"].as_str().unwrap();
        let (ordinal, width) =
            (link["from"]["ordinal"].as_u64().unwrap(), link["from"]["width"].as_u64().unwrap());
        let value = guest(&board, &frames::read_link(a));
        assert_eq!(value["resp"].as_str(), Some("link_value"), "{value}");
        let ty = &value["link"]["slots"][2];
        assert_eq!(
            ty,
            &serde_json::json!([{"start": CITATION_TYPE, "width": "0.0.0.0.0.0.0.0.1"}]),
            "the citation type: {value}"
        );
        let follow = guest(&board, &serde_json::json!({"op": "follow_link", "a": a, "slot": 1}));
        let spans = follow["result"]["ok"].as_array().unwrap_or_else(|| panic!("{follow}"));
        assert_eq!(spans.len(), 1, "{follow}");
        assert_eq!(
            spans[0]["start"],
            format!("{home}.0.1.{ordinal}"),
            "the from-end is the cite's own span"
        );
        assert_eq!(
            spans[0]["width"].as_str().unwrap().rsplit('.').next().unwrap(),
            width.to_string()
        );
        let doc_index = editions.iter().position(|e| e == home).unwrap();
        let bytes = &cut.documents[doc_index].document.bytes;
        let token = &bytes[ordinal as usize - 1..(ordinal + width - 1) as usize];
        assert_eq!(
            std::str::from_utf8(token).unwrap(),
            link["cite"].as_str().unwrap().to_string()
                + &link["section"].as_str().map(|s| format!(" §{s}")).unwrap_or_default(),
            "the span is the cite's token"
        );
        if link["cite"] == "nowhere.md" {
            ghosts += 1;
            assert_eq!(to, ghost);
            let meta = guest(&board, &frames::doc_metadata(to));
            assert_eq!(rejected(&meta), Some("doc_not_registered"), "{meta}");
            continue;
        }
        if link["cite"] == "a.md" && link["section"] == "1.2" {
            sectioned += 1;
            assert_eq!(
                to, editions[section_document],
                "the sectioned cite lands on the document holding the section"
            );
        }
        let projected =
            guest(&board, &serde_json::json!({"op": "project", "a": a, "slot": 2, "d": to}));
        assert_eq!(projected["resp"].as_str(), Some("span_set"), "{projected}");
        assert!(
            !projected["set"].as_array().unwrap().is_empty(),
            "the to-end projects into the cited edition: {projected}"
        );
    }
    assert!(sectioned >= 1 && ghosts >= 2, "{sectioned} sectioned cites, {ghosts} ghosts");

    // F3: the versions.
    let compare = |a: &str, na: u64, b: &str, nb: u64| -> Vec<(u64, u64, u64)> {
        let v = guest(
            &board,
            &frames::compare(&[frames::region(a, 1, na)], &[frames::region(b, 1, nb)]),
        );
        assert_eq!(v["resp"].as_str(), Some("compare"), "{v}");
        v["pairs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["u1"]["ordinal"].as_str().unwrap().parse().unwrap(),
                    p["u2"]["ordinal"].as_str().unwrap().parse().unwrap(),
                    p["width"].as_str().unwrap().parse().unwrap(),
                )
            })
            .collect()
    };
    // (a) APPENDED, with the window, on the first edition.
    let e = &editions[0];
    let one = &cut.documents[0].document.bytes;
    let n = one.len() as u64;
    let next = &cut.documents[1].paragraphs[0];
    let appended =
        [b"\n\n".as_slice(), &cut.documents[1].document.bytes[next.offset..next.offset + next.len]]
            .concat();
    let m = appended.len() as u64;
    let head = read_guest(&board, e);
    let two = read_guest(&board, &format!("{e}.2"));
    assert_eq!(head, two, "the bare address floats to E.2");
    assert_eq!(extent(&board, e), n + 240 + m);
    let got = items(&two);
    let (mut text, mut withheld) = (Vec::new(), Vec::new());
    for item in got {
        match item {
            Item::Text(b) => text.push(b),
            w => withheld.push(w),
        }
    }
    assert_eq!(
        withheld,
        vec![Item::Withheld { width: 240, origin: "1.0.1.0.15".into() }],
        "the windowed run is withheld from a guest to the width, naming its origin"
    );
    assert_eq!(
        text.concat(),
        [one.as_slice(), &appended].concat(),
        "the edition's own run and the appended paragraph"
    );
    let mine = text_of(&read_as(&board, &claimant, &format!("{e}.2")));
    assert_eq!(
        mine,
        [one.as_slice(), &cut.documents[12].document.bytes[..240], &appended].concat(),
        "the claimant reads the window's bytes"
    );
    assert_eq!(
        compare(&format!("{e}.1"), n, &format!("{e}.2"), n + 240 + m),
        vec![(1, 1, n)],
        "E.1 whole in E.2"
    );
    // (b) REMOVED on the fifth: shorter by one paragraph that holds a cite,
    // and the link in it floats.
    let e = &editions[4];
    let five = &cut.documents[4].document.bytes;
    let n = five.len() as u64;
    let dropped = manifest_item(&manifest, "cut-00005:version:shot");
    assert_eq!(dropped["arm"], "removed");
    let (off, len) = (
        dropped["dropped"]["offset"].as_u64().unwrap() as usize,
        dropped["dropped"]["len"].as_u64().unwrap() as usize,
    );
    assert!(len > 0 && off + len <= five.len());
    let two = text_of(&read_guest(&board, &format!("{e}.2")));
    assert_eq!(
        two,
        [&five[..off], &five[off + len..]].concat(),
        "E.2 is E.1 minus the dropped paragraph"
    );
    assert_eq!(text_of(&read_guest(&board, e)), two, "the bare address floats");
    let in_dropped: Vec<&Value> = links
        .iter()
        .filter(|l| {
            l["home"].as_str() == Some(e)
                && (l["from"]["ordinal"].as_u64().unwrap() as usize - 1) >= off
                && (l["from"]["ordinal"].as_u64().unwrap() as usize - 1) < off + len
        })
        .collect();
    assert!(!in_dropped.is_empty(), "the dropped paragraph holds a cite");
    for l in &in_dropped {
        let projected =
            guest(&board, &serde_json::json!({"op": "project", "a": l["addr"], "slot": 1, "d": e}));
        assert_eq!(projected["resp"].as_str(), Some("span_set"), "{projected}");
        assert!(
            projected["set"].as_array().unwrap().is_empty(),
            "the link's from-end floats: {projected}"
        );
    }
    let kept: Vec<&Value> = links
        .iter()
        .filter(|l| l["home"].as_str() == Some(e) && !in_dropped.contains(&*l))
        .collect();
    for l in kept {
        let projected =
            guest(&board, &serde_json::json!({"op": "project", "a": l["addr"], "slot": 1, "d": e}));
        assert!(
            !projected["set"].as_array().unwrap().is_empty(),
            "a link outside the dropped paragraph stands: {projected}"
        );
    }
    let mut want = Vec::new();
    if off > 0 {
        want.push((1, 1, off as u64));
    }
    if off + len < five.len() {
        want.push(((off + len + 1) as u64, (off + 1) as u64, (five.len() - off - len) as u64));
    }
    assert_eq!(
        compare(&format!("{e}.1"), n, &format!("{e}.2"), two.len() as u64),
        want,
        "the kept runs correspond"
    );
    // (c) CHANGED on the ninth: one sentence replaced between two reference runs.
    let e = &editions[8];
    let nine = &cut.documents[8].document.bytes;
    let n = nine.len() as u64;
    let changed = manifest_item(&manifest, "cut-00009:version:shot");
    assert_eq!(changed["arm"], "changed");
    assert_eq!(changed["with"], CHANGED);
    let (a, len) = (
        changed["replaced"]["offset"].as_u64().unwrap() as usize,
        changed["replaced"]["len"].as_u64().unwrap() as usize,
    );
    assert!(
        a > 0 && len > 0 && a + len < nine.len(),
        "a sentence inside the document: {a}+{len} of {}",
        nine.len()
    );
    assert!(nine[a + len - 1] == b'.', "the replaced stretch ends at a sentence's period");
    let two = text_of(&read_guest(&board, &format!("{e}.2")));
    assert_eq!(
        two,
        [&nine[..a], CHANGED.as_bytes(), &nine[a + len..]].concat(),
        "E.2 is E.1 with the sentence changed"
    );
    assert_eq!(
        compare(&format!("{e}.1"), n, &format!("{e}.2"), two.len() as u64),
        vec![
            (1, 1, a as u64),
            ((a + len + 1) as u64, (a + CHANGED.len() + 1) as u64, (nine.len() - a - len) as u64)
        ]
    );

    // F4: the drafts answer the claimant and are withheld from a guest; the
    // second account's draft is withheld from the claimant too.
    for (j, draft) in ["1.0.1.0.15", "1.0.1.0.16", "1.0.1.0.17"].iter().enumerate() {
        let want = &cut.documents[DOCUMENTS + j].document.bytes;
        let mine = under(&board, &claimant, &frames::retrieve_v(draft, 1, want.len() as u64));
        assert_eq!(text_of(&mine), *want, "{draft} for the claimant");
        let theirs = guest(&board, &frames::retrieve_v(draft, 1, want.len() as u64));
        assert_eq!(rejected(&theirs), Some("withheld"), "{theirs}");
        assert_eq!(theirs["site"]["addr"], *draft, "{theirs}");
    }
    let second_draft = "1.0.2.0.2";
    let want = &cut.documents[DOCUMENTS + DRAFTS].document.bytes;
    let refused = under(&board, &claimant, &frames::retrieve_v(second_draft, 1, want.len() as u64));
    assert_eq!(
        rejected(&refused),
        Some("withheld"),
        "the claimant cannot read the second account's draft: {refused}"
    );
    assert_eq!(refused["site"]["addr"], second_draft);
    let second = bare(&board, 2);
    assert_eq!(
        text_of(&under(&board, &second, &frames::retrieve_v(second_draft, 1, want.len() as u64))),
        *want,
        "its own principal reads it"
    );
    let home = guest(&board, &frames::doc_metadata("1.0.2.0.1"));
    assert_eq!(
        (home["published"].as_bool(), home["owner"].as_str()),
        (Some(true), Some("1.0.2")),
        "{home}"
    );

    // F8: the agent space holds no document after the run.
    let agent = guest(&board, &frames::doc_metadata("1.0.1.1.0.2"));
    assert_eq!(rejected(&agent), Some("doc_not_registered"), "{agent}");

    // F5: a second run adds nothing and says so — on stderr as it opens the
    // manifest, and in the object.
    let before = log_position(&board);
    let r = skep_dev(&args);
    let again = parse_json(&r);
    assert_eq!(again["already_seeded"], true);
    assert!(
        r.err.contains("records every write of this seed (")
            && r.err.contains("): this run writes nothing"),
        "{}",
        r.err
    );
    assert_eq!(log_position(&board), before, "no write");
    assert_eq!(again["positions"]["before"], before);
    assert_eq!(again["positions"]["after"], before);
    assert_eq!(shape(&again), shape(&v), "the same object");

    // Another seed of this board is refused: the manifest's key.
    let mut other = args.clone();
    assert_eq!(other[10], "12");
    other[10] = "11";
    let r = skep_dev(&other);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(
        r.err.contains("records another seed of this board")
            && r.err.contains("documents: 12 recorded, 11 asked"),
        "{}",
        r.err
    );
    assert_eq!(log_position(&board), before, "no write");
}

/// A daemon over `dir`, CLAIMED-PERMISSIVE, accepting signed sessions at its
/// own origin and at each of `also` — a proxy's — as `common::spawn` spawns
/// one at its own alone: the daemon's own start (`skepd::embed`), the port
/// bound first and named in the origin, then the wait for its cell index.
fn spawn_also_at(dir: &Path, also: &[String]) -> Skepd {
    let configured = |port: u16| {
        let mut opts = AuthOptions::default();
        opts.local_trust = true;
        opts.configured = std::iter::once(origin(port))
            .chain(also.iter().cloned())
            .map(|o| skepd::Origin::parse(&o).expect("a canonical origin"))
            .collect();
        opts
    };
    let sd = embed(dir, 0, configured, MediaOptions::default(), DEFAULT_WORKERS)
        .unwrap_or_else(|e| panic!("daemon start at {}: {e}", dir.display()));
    sd.wait_for_the_index(Duration::from_secs(60)).unwrap_or_else(|e| panic!("{e}"));
    sd
}

/// A proxy in front of the daemon that pipes every request whole until, while
/// `armed`, one whose body holds `cut_at`: that one it drops unforwarded —
/// the connection closed, the daemon never sees it — and every connection
/// after, until the test disarms it and clears `tripped`. Its listener is
/// bound ahead of the daemon, so the daemon can be configured for its origin.
fn cutting_proxy(
    listener: TcpListener,
    upstream: u16,
    cut_at: &'static str,
    armed: Arc<AtomicBool>,
    tripped: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(mut client) = client else { continue };
            if tripped.load(Ordering::SeqCst) {
                let _ = client.shutdown(Shutdown::Both);
                continue;
            }
            let (mut seen, mut buf) = (Vec::new(), [0u8; 8192]);
            let body_at = loop {
                if let Some(head_len) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(head_len + 4);
                }
                match client.read(&mut buf) {
                    Ok(n @ 1..) => seen.extend_from_slice(&buf[..n]),
                    _ => break None,
                }
            };
            let Some(body_at) = body_at else { continue };
            let head = String::from_utf8_lossy(&seen[..body_at]).into_owned();
            let declared: usize = head
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, n)| n.trim().parse().ok())
                })
                .unwrap_or(0);
            while seen.len() < body_at + declared {
                match client.read(&mut buf) {
                    Ok(n @ 1..) => seen.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            if armed.load(Ordering::SeqCst)
                && String::from_utf8_lossy(&seen[body_at..]).contains(cut_at)
            {
                tripped.store(true, Ordering::SeqCst);
                let _ = client.shutdown(Shutdown::Both);
                continue;
            }
            let Ok(mut server) = TcpStream::connect(("127.0.0.1", upstream)) else { continue };
            if server.write_all(&seen).is_err() {
                continue;
            }
            let _ = server.shutdown(Shutdown::Write);
            let _ = std::io::copy(&mut server, &mut client);
            let _ = client.shutdown(Shutdown::Write);
        }
    });
}

/// F5: a run cut short at its fifth document — the connection dropped at
/// the first write naming it — stops with transport's exit, its manifest
/// holding the four documents landed; the next run resumes at the fifth and
/// lands what a one-shot run lands, and a third adds nothing. The board is
/// claimed and seeded THROUGH the proxy, whose origin the daemon is
/// configured for and the store's binding names.
#[test]
fn a_run_cut_short_resumes_and_lands_what_a_one_shot_run_lands() {
    let dir: TempDir = tempfile::tempdir().unwrap();
    let (repo, pin, cut) = repository(dir.path());
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the proxy's port");
    let proxied = origin(listener.local_addr().unwrap().port());
    let sd = spawn_also_at(&dir.path().join("board"), std::slice::from_ref(&proxied));
    let armed = Arc::new(AtomicBool::new(true));
    let tripped = Arc::new(AtomicBool::new(false));
    cutting_proxy(
        listener,
        sd.port(),
        "\"id\":\"cut-00005:draft\"",
        Arc::clone(&armed),
        Arc::clone(&tripped),
    );
    let board = board_at(&origin(sd.port()));
    let store = dir.path().join("store");
    claim_board(&proxied, &store, &dir.path().join("anchors"));

    let args = seed_args(&proxied, s(&store), s(&repo), &pin);
    let r = skep_dev(&args);
    assert_eq!(r.code, 4, "transport's exit when the connection is dropped: {r:?}");
    assert!(r.out.is_empty(), "no JSON on a failed run: {}", r.out);
    assert!(r.err.contains("a new seed of this board"), "the manifest's line: {}", r.err);
    assert!(
        r.err.contains("\n  act: ") && r.err.contains("read back what"),
        "the transport halt's act: the write may stand, read it back: {}",
        r.err
    );
    let chain: String =
        board.board_term().unwrap().unwrap().chain.iter().map(|b| format!("{b:02x}")).collect();
    let manifest = dir.path().join("store-seed").join(format!("{chain}.jsonl"));
    let text = std::fs::read_to_string(&manifest).expect("the manifest holds what landed");
    let ids: Vec<String> = text
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains(&"cut-00004:shot".to_string())
            && !ids.iter().any(|id| id.starts_with("cut-00005")),
        "four documents landed and recorded: {ids:?}"
    );
    assert_eq!(
        ids.len(),
        1 + 4 * 3,
        "the staging draft and four documents' three writes each: {ids:?}"
    );

    armed.store(false, Ordering::SeqCst);
    tripped.store(false, Ordering::SeqCst);
    let r = skep_dev(&args);
    let v = parse_json(&r);
    assert_eq!(v["already_seeded"], false);
    assert_expected_shape(&v, &cut);
    assert!(r.err.contains("mode CLAIMED-PERMISSIVE"), "{}", r.err);
    // The resume says what it resumes after, and the one write it cannot see:
    // the one the stopped run had in flight, made again under a new session.
    assert!(
        r.err.contains("holds 13 lines of this seed: the run resumes after them")
            && r.err.contains("it is made again here, and a mint or a shot then lands twice"),
        "the manifest's line at a resume: {}",
        r.err
    );
    for i in 0..DOCUMENTS {
        let want = &cut.documents[i].document.bytes;
        let e = format!("1.0.1.0.{}.1", i + 3);
        assert_eq!(text_of(&read_guest(&board, &e)), *want, "{e} byte-exact after the resume");
    }
    let before = log_position(&board);
    let r = skep_dev(&args);
    let again = parse_json(&r);
    assert_eq!(again["already_seeded"], true);
    assert!(r.err.contains("records every write of this seed"), "{}", r.err);
    assert_eq!(log_position(&board), before);
    assert_eq!(shape(&again), shape(&v));
}

/// The dev binary's grammar through argv: `--help` is DATA naming the verb,
/// an unknown verb is exit 2 with the help beneath, a count that is no count
/// is exit 2 before any socket, and a repository that is no directory is
/// exit 2 before the board is dialed.
#[test]
fn help_is_data_and_a_refused_command_line_is_exit_2_before_any_socket() {
    let r = skep_dev(&["--help"]);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        r.err.is_empty()
            && r.out.starts_with("usage: skep-dev <command> [flags]\n")
            && r.out.contains("\n  seed "),
        "{r:?}"
    );
    let r = skep_dev(&["frob"]);
    assert_eq!(r.code, 2);
    assert!(
        r.err
            .starts_with("skep-dev: unknown command `frob`\n\nusage: skep-dev <command> [flags]\n"),
        "{}",
        r.err
    );
    assert!(r.out.is_empty());
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep_dev(&[
        "seed",
        "--board",
        "http://127.0.0.1:1",
        "--dir",
        s(&store),
        "--repo",
        "/",
        "--documents",
        "0",
    ]);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("--documents: '0' is not a count of at least one"), "{}", r.err);
    let r = skep_dev(&[
        "seed",
        "--board",
        "http://127.0.0.1:1",
        "--dir",
        s(&store),
        "--repo",
        "/no/such/repository",
    ]);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("is not a directory"), "{}", r.err);
    let r = skep_dev(&["seed", "--repo", "/"]);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("--board (or SKEP_BOARD) is required"), "{}", r.err);
    let r = skep_dev(&["seed", "--board", "http://127.0.0.1:1", "--repo", "/"]);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(
        r.err.contains("--dir (or SKEP_KEYSTORE) is required"),
        "no HOME, no default store: {}",
        r.err
    );
    // A directory that is no repository, or a pin it does not hold: a halt,
    // ahead of any socket — the board above answers nobody.
    let r = skep_dev(&[
        "seed",
        "--board",
        "http://127.0.0.1:1",
        "--dir",
        s(&store),
        "--repo",
        s(dir.path()),
        "--pin",
        "abcdef0",
    ]);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("the corpus cannot be read at abcdef0"), "{}", r.err);
}
