//! The crate's unit claims: the tier's filter and the paragraph cap as pure
//! functions, and the cut over a repository the suite builds under the
//! system temp dir — `git init`, one commit — so the rule is checked over
//! bytes the test chose, with no corpus of the world's in the tree.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

use super::*;

#[test]
fn the_tier_excludes_context_bundles_and_media_and_nothing_else() {
    assert!(in_tier("search.md"));
    assert!(in_tier("_designs/QUEUE.md"));
    assert!(in_tier("spikes/s11/results/chrome-3.json"));
    assert!(in_tier("designs/reviews/foundations/sweep-1/_skep_ref"));
    assert!(!in_tier("_designs/SEARCH/_context.search.md"));
    assert!(!in_tier("_context.md"));
    assert!(!in_tier("ux/mock.PNG"));
    assert!(!in_tier("spikes/s3/media/run.mp4"));
    assert!(!in_tier("a/b.webm"));
}

#[test]
fn a_paragraph_is_capped_on_a_character_boundary() {
    let long = "é".repeat(PARAGRAPH_CAP);
    let cut = capped(&long);
    assert!(cut.len() <= PARAGRAPH_CAP);
    assert!(cut.len() >= PARAGRAPH_CAP - 1);
    assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
    assert_eq!(capped("short"), "short");
}

#[test]
fn a_path_is_under_a_subtree_by_whole_components() {
    assert!(under_subtree("ux/a.md", "ux"));
    assert!(under_subtree("ux/a.md", "ux/"));
    assert!(under_subtree("ux/deep/a.md", "ux"));
    assert!(under_subtree("ux", "ux"));
    assert!(under_subtree("anything.md", ""));
    assert!(!under_subtree("uxx/a.md", "ux"));
    assert!(!under_subtree("a/ux/b.md", "ux"));
    assert!(!under_subtree("README.md", "ux"));
}

#[test]
fn a_heading_is_the_first_lines_text_after_the_marks() {
    assert_eq!(
        heading_of("## 1.2 The second section\nbody"),
        Some("1.2 The second section".into())
    );
    assert_eq!(heading_of("# Title"), Some("Title".into()));
    assert_eq!(heading_of("###"), None);
    assert_eq!(heading_of("plain prose\n## not a heading"), None);
}

// ── A REPOSITORY OF THE SUITE's OWN ─────────────────────────────────────

/// One paragraph of deterministic prose, about 500 bytes, numbered so the
/// cut's order can be read off the documents.
fn prose(file: &str, i: usize) -> String {
    let mut p = format!("Paragraph {i} of {file}.");
    let mut w = 0;
    while p.len() < 480 {
        p.push_str(
            [" The board holds prose.", " A guest reads the editions.", " Links carry the cites."]
                [w % 3],
        );
        w += 1;
    }
    p
}

/// A file of `n` paragraphs, parted by blank lines of varied width.
fn prose_file(file: &str, n: usize) -> String {
    (0..n).map(|i| prose(file, i)).collect::<Vec<_>>().join(if n % 2 == 0 {
        "\n\n"
    } else {
        "\n   \n\n"
    })
}

/// Runs the suite's own `git -C <repo>` with `args` and returns its stdout.
///
/// The stdout comes back trimmed. No person's configuration reaches the
/// command, and none of [`GIT_LOCAL_VARIABLES`]: an exported `GIT_DIR`
/// would make the temp dir the work tree of the repository it names, and
/// the fixture's commit would land there.
///
/// # Panics
///
/// Where git cannot be run, or fails.
fn git(repo: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
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
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for name in GIT_LOCAL_VARIABLES {
        cmd.env_remove(name);
    }
    let out = cmd.output().expect("git runs");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository under the system temp dir holding `files`, committed once;
/// the commit's hash.
fn repository(files: &[(&str, &[u8])]) -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("a temp dir");
    for (path, bytes) in files {
        let at = tmp.path().join(path);
        std::fs::create_dir_all(at.parent().expect("a parent")).expect("the directory");
        std::fs::write(&at, bytes).expect("the file");
    }
    git(tmp.path(), &["init", "-q"]);
    git(tmp.path(), &["add", "-A"]);
    git(tmp.path(), &["commit", "-q", "-m", "the corpus"]);
    let head = git(tmp.path(), &["rev-parse", "HEAD"]);
    (tmp, head)
}

/// The suite's corpus: three prose files and a fourth under `ux/`, a bundle
/// and an image the tier excludes, a text file the tier holds that is no
/// paragraph source, one heading, and one paragraph past the cap.
fn files() -> Vec<(String, Vec<u8>)> {
    let long = "x".repeat(PARAGRAPH_CAP + 1_000);
    let a = format!(
        "# a.md\n\n{}\n\n## 1.2 The second section\n\nThe section's own paragraph.\n\n{}\n\n{}",
        prose_file("a", 6),
        long,
        prose_file("a-tail", 20)
    );
    vec![
        ("README.md".to_string(), prose_file("README", 4).into_bytes()),
        ("_designs/a.md".to_string(), a.into_bytes()),
        ("_designs/b.md".to_string(), prose_file("b", 30).into_bytes()),
        ("_context.all.md".to_string(), b"excluded bundle".to_vec()),
        ("notes.txt".to_string(), b"in the tier, no paragraph source".to_vec()),
        ("ux/c.md".to_string(), prose_file("c", 30).into_bytes()),
        ("ux/shot.PNG".to_string(), vec![0x89, b'P', b'N', b'G']),
    ]
}

fn suite_repository() -> (TempDir, String) {
    let files = files();
    let borrowed: Vec<(&str, &[u8])> =
        files.iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect();
    repository(&borrowed)
}

#[test]
fn the_tier_at_the_pin_is_every_tracked_file_but_the_excluded_and_the_records_are_their_bytes() {
    let (tmp, head) = suite_repository();
    let corpus = Corpus::open(tmp.path(), &head).expect("the pin is a commit");
    let tier = corpus.tier().expect("ls-tree");
    let paths: Vec<&str> = tier.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        ["README.md", "_designs/a.md", "_designs/b.md", "notes.txt", "ux/c.md"],
        "ls-tree order, the bundle and the image out"
    );
    let records = corpus.records().expect("the blobs");
    for (entry, doc) in tier.iter().zip(&records) {
        assert_eq!(doc.name, entry.path);
        assert_eq!(doc.bytes.len() as u64, entry.size, "{}", entry.path);
    }
    assert_eq!(records[3].bytes, b"in the tier, no paragraph source");
    assert_eq!(total_bytes(&records), tier.iter().map(|e| e.size).sum::<u64>());
    assert_eq!(
        corpus.markdown().unwrap(),
        ["README.md", "_designs/a.md", "_designs/b.md", "ux/c.md"]
    );
    assert_eq!(
        corpus.sources().unwrap(),
        corpus.markdown().unwrap(),
        "the whole tier is the source"
    );
    assert_eq!(corpus.rule(), CUT_RULE);
    assert_eq!((corpus.pin(), corpus.subtree()), (head.as_str(), None));
}

#[test]
fn the_cut_takes_the_tiers_paragraphs_in_order_to_the_targets_and_names_its_sources() {
    let (tmp, head) = suite_repository();
    let corpus = Corpus::open(tmp.path(), &head).unwrap();
    // Nine cut, the first eight judged: the target check reads the NEXT
    // document's first paragraph.
    let cut = corpus.cut_sourced(9).expect("nine documents");
    assert_eq!(cut.sources, ["README.md", "_designs/a.md", "_designs/b.md", "ux/c.md"]);
    assert_eq!(cut.documents.len(), 9);
    let mut all: Vec<&Paragraph> = Vec::new();
    for (i, sourced) in cut.documents.iter().enumerate().take(8) {
        let doc = &sourced.document;
        assert_eq!(doc.name, format!("cut-{:05}", i + 1));
        assert!(
            (CUT_MIN..=CUT_MAX).contains(&doc.bytes.len()),
            "{}: {} bytes",
            doc.name,
            doc.bytes.len()
        );
        // The paragraphs' ranges reconstruct the bytes, parted by one blank line.
        let mut rebuilt = Vec::new();
        for (j, p) in sourced.paragraphs.iter().enumerate() {
            if j > 0 {
                rebuilt.extend_from_slice(b"\n\n");
            }
            assert_eq!(p.offset, rebuilt.len(), "{}: paragraph {j} offset", doc.name);
            rebuilt.extend_from_slice(&doc.bytes[p.offset..p.offset + p.len]);
            assert!(p.len <= PARAGRAPH_CAP);
        }
        assert_eq!(rebuilt, doc.bytes, "{}", doc.name);
        // The target: reached, or the next paragraph would pass CUT_MAX.
        let target = CUT_MIN * (1 + (7 * i) % 10);
        let next = cut.documents.get(i + 1).and_then(|s| s.paragraphs.first()).map(|p| p.len);
        assert!(
            doc.bytes.len() >= target || next.is_some_and(|n| doc.bytes.len() + 2 + n > CUT_MAX),
            "{}: {} bytes against the target {target}, next {next:?}",
            doc.name,
            doc.bytes.len()
        );
        all.extend(&sourced.paragraphs);
    }
    // The source order: README's four paragraphs first, then a.md's.
    let files: Vec<&str> = all.iter().map(|p| p.file.as_str()).collect();
    assert_eq!(&files[..4], ["README.md"; 4]);
    assert_eq!(files[4], "_designs/a.md");
    assert!(files.windows(2).all(|w| w[0] <= w[1]), "files in ls-tree order: {files:?}");
    assert!(std::str::from_utf8(&cut.documents[0].document.bytes)
        .unwrap()
        .starts_with("Paragraph 0 of README."));
    // The heading is recorded on the paragraph that opens it.
    let heading = all
        .iter()
        .find(|p| p.heading.as_deref() == Some("1.2 The second section"))
        .expect("the heading");
    assert_eq!(heading.file, "_designs/a.md");
    assert_eq!(
        all.iter().find(|p| p.heading.as_deref() == Some("a.md")).map(|p| p.file.as_str()),
        Some("_designs/a.md")
    );
    // The paragraph past the cap is cut at the cap.
    let capped = all.iter().find(|p| p.len == PARAGRAPH_CAP).expect("the capped paragraph");
    assert_eq!(capped.file, "_designs/a.md");
    assert!(all.iter().all(|p| p.len <= PARAGRAPH_CAP));
    // A shorter cut is a prefix of a longer one, and the documents alone are the sourced ones'.
    let three = corpus.cut(3).unwrap();
    assert_eq!(three.len(), 3);
    for (d, s) in three.iter().zip(&cut.documents) {
        assert_eq!(*d, s.document);
    }
    assert_eq!(corpus.cut(0).unwrap(), Vec::<Document>::new());
    // The source runs out: a shortfall, never a panic.
    match corpus.cut(10_000) {
        Err(Error::Short { cut, wanted }) => {
            assert!(cut >= 8 && wanted == 10_000, "{cut} of {wanted}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_subtree_restricts_the_source_and_names_the_rule_cut_v2() {
    let (tmp, head) = suite_repository();
    let corpus = Corpus::open(tmp.path(), &head).unwrap().under("ux/");
    assert_eq!(corpus.rule(), CUT_RULE_SUBTREE);
    assert_eq!(corpus.subtree(), Some("ux"));
    assert_eq!(corpus.sources().unwrap(), ["ux/c.md"]);
    assert_eq!(corpus.markdown().unwrap().len(), 4, "the tier is the whole repository still");
    let cut = corpus.cut_sourced(2).unwrap();
    assert_eq!(cut.sources, ["ux/c.md"]);
    assert!(cut.documents.iter().flat_map(|s| &s.paragraphs).all(|p| p.file == "ux/c.md"));
    assert!(std::str::from_utf8(&cut.documents[0].document.bytes)
        .unwrap()
        .starts_with("Paragraph 0 of c."));
    let whole = Corpus::open(tmp.path(), &head).unwrap().cut(1).unwrap();
    assert_ne!(whole[0].bytes, cut.documents[0].document.bytes, "another source, other documents");
    let nowhere = Corpus::open(tmp.path(), &head).unwrap().under("nowhere");
    assert_eq!(nowhere.cut(1), Err(Error::Short { cut: 0, wanted: 1 }));
}

#[test]
fn the_pin_is_judged_at_open_and_the_bytes_are_the_commits_not_the_trees() {
    let (tmp, head) = suite_repository();
    match Corpus::open(tmp.path(), "0000000") {
        Err(Error::NoCommit { pin, .. }) => assert_eq!(pin, "0000000"),
        other => panic!("{other:?}"),
    }
    // The repository is judged before the pin, and its refusal is git's
    // own: an absent path, and a directory that is no repository, whatever
    // the pin.
    match Corpus::open(tmp.path().join("absent"), &head) {
        Err(Error::Git { command, said }) => {
            assert!(command.ends_with("rev-parse --git-dir"), "{command}");
            assert!(!said.trim().is_empty(), "git's own words");
        }
        other => panic!("an absent path: {other:?}"),
    }
    let empty = tempfile::tempdir().expect("a temp dir");
    match Corpus::open(empty.path(), "0000000") {
        Err(Error::Git { command, said }) => {
            assert!(command.ends_with("rev-parse --git-dir"), "{command}");
            assert!(!said.trim().is_empty(), "git's own words");
        }
        other => panic!("a directory that is no repository: {other:?}"),
    }
    let corpus = Corpus::open(tmp.path(), &head[..8]).expect("an abbreviated pin resolves");
    let before = corpus.cut(1).unwrap();
    std::fs::write(tmp.path().join("README.md"), "the working tree moved on\n").unwrap();
    assert_eq!(corpus.cut(1).unwrap(), before, "the working tree is never read");
    git(tmp.path(), &["commit", "-q", "-a", "-m", "moved"]);
    assert_eq!(corpus.cut(1).unwrap(), before, "a later commit does not move the pin");
    let later = git(tmp.path(), &["rev-parse", "HEAD"]);
    let moved = Corpus::open(tmp.path(), &later).unwrap();
    assert_ne!(moved.cut(1).unwrap(), before, "the new pin reads the new bytes");
    assert_eq!(moved.records().unwrap()[0].bytes, b"the working tree moved on\n");
}

// ── GIT'S OWN VARIABLES ─────────────────────────────────────────────────

/// Checks that a decoy's `GIT_DIR` and its kin move no read and no write.
///
/// `GIT_DIR`, `GIT_COMMON_DIR`, the object and alternate directories, the
/// work tree and the index all name a decoy repository, as a hook's
/// exports name the hook's: the pin, by name and by hash, is judged and
/// read in the repository named all the same, the decoy's head is no
/// commit of it, and a repository the suite builds holds what it wrote
/// while the decoy stands as it was. Judged in a child of this test binary
/// (skepd's self-exec pattern), because the variables are process-wide and
/// the suite's other claims run beside this one; the child prints a line
/// its parent reads, so a child that ran no test is no pass.
#[test]
fn a_repository_variable_in_the_environment_never_moves_the_read() {
    const CHILD: &str = "SKEP_CORPUS_TEST_CHILD";
    const HELD: &str = "the child's claims held";
    if let Some(given) = std::env::var_os(CHILD) {
        // The child: the parent named the repository, its head, the decoy
        // and the decoy's head, one to a line.
        let given = given.into_string().expect("the parent's lines are text");
        let lines: Vec<&str> = given.lines().collect();
        let [named, head, decoy, decoy_head] = lines[..] else {
            panic!("four lines from the parent: {given:?}");
        };
        let (named, decoy) = (Path::new(named), Path::new(decoy));
        let by_name =
            Corpus::open(named, "HEAD").expect("HEAD is a commit of the repository named");
        let readme = &by_name.records().expect("the blobs")[0];
        assert_eq!(
            (readme.name.as_str(), String::from_utf8_lossy(&readme.bytes)),
            ("README.md", prose_file("README", 4).into()),
            "the README read at HEAD is the named repository's"
        );
        let by_hash = Corpus::open(named, head).expect("the named head is a commit of it");
        assert_eq!(
            by_hash.markdown().expect("ls-tree"),
            ["README.md", "_designs/a.md", "_designs/b.md", "ux/c.md"]
        );
        match Corpus::open(named, decoy_head) {
            Err(Error::NoCommit { pin, .. }) => assert_eq!(pin, decoy_head),
            other => panic!("the decoy's head opened in the repository named: {other:?}"),
        }
        let prose = b"the built repository's prose\n";
        let (built, built_head) = repository(&[("x.md", prose)]);
        let records = Corpus::open(built.path(), &built_head).unwrap().records().unwrap();
        assert_eq!(
            records,
            [Document { name: "x.md".into(), bytes: prose.to_vec() }],
            "the suite's commit holds what it wrote"
        );
        assert_eq!(git(decoy, &["rev-parse", "HEAD"]), decoy_head, "the decoy's head stands");
        assert_eq!(git(decoy, &["status", "--porcelain"]), "", "the decoy's index and tree stand");
        println!("{HELD}");
        return;
    }
    let (named, head) = suite_repository();
    let (decoy, decoy_head) = repository(&[("README.md", b"the decoy's own prose\n")]);
    let decoy_git = decoy.path().join(".git");
    let given =
        format!("{}\n{head}\n{}\n{decoy_head}", named.path().display(), decoy.path().display());
    let exe = std::env::current_exe().expect("the test binary");
    let out = Command::new(exe)
        .args([
            "tests::a_repository_variable_in_the_environment_never_moves_the_read",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, given)
        .env("GIT_DIR", &decoy_git)
        .env("GIT_COMMON_DIR", &decoy_git)
        .env("GIT_OBJECT_DIRECTORY", decoy_git.join("objects"))
        .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", decoy_git.join("objects"))
        .env("GIT_WORK_TREE", decoy.path())
        .env("GIT_INDEX_FILE", decoy_git.join("index"))
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains(HELD),
        "the child's claims did not all run and hold:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Checks that the crate's `git` clears git's repository-local variables.
///
/// Every name `git rev-parse --local-env-vars` prints is cleared but the
/// two that carry configuration, which are kept; the list read is git's
/// own, so a git that grows it fails here until [`GIT_LOCAL_VARIABLES`]
/// names the new one. The command clears that constant whole.
#[test]
fn every_git_the_crate_runs_starts_without_the_repository_local_variables() {
    let listed =
        Command::new("git").args(["rev-parse", "--local-env-vars"]).output().expect("git runs");
    assert!(listed.status.success(), "{}", String::from_utf8_lossy(&listed.stderr));
    let listed = String::from_utf8(listed.stdout).expect("the names are text");
    let corpus = Corpus { repo: PathBuf::from("."), pin: "HEAD".into(), subtree: None };
    let cmd = corpus.git();
    let cleared: BTreeSet<&str> = cmd
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .map(|(name, _)| name.to_str().expect("a variable's name is text"))
        .collect();
    assert!(listed.lines().count() > 2, "git lists its variables: {listed:?}");
    for name in listed.lines() {
        if ["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"].contains(&name) {
            assert!(!cleared.contains(name), "{name} carries configuration, and is kept");
        } else {
            assert!(cleared.contains(name), "git lists {name} as repository-local: clear it");
        }
    }
    assert_eq!(cleared, BTreeSet::from(GIT_LOCAL_VARIABLES), "the one list, cleared whole");
}
