//! Scenario loading: walk `conformance/golden/<category>/<name>.json`, parse
//! each file as dynamic JSON (`{ name, description, operations: [...] }`
//! where every operation is a loose field-bag). Every failure is a hard
//! loader error ([`LoadError`]) — the goldens are vendored data; a directory
//! that does not list or a file that does not read or parse means the
//! vendoring broke, not the systems, and so do two scenarios sharing one key
//! ([`Scenario::key`]), which no adjudication could tell apart, and a file
//! placed where the sweep would never play it. [`conformance_dir`] locates
//! the vendored tree the goldens and the allowlist live in.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::outcome::ScenarioKey;

/// `skep/conformance/` located from this crate — the golden tree and the
/// allowlist live here.
pub fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

#[derive(Clone, Debug)]
pub struct Scenario {
    pub category: String,
    pub name: String,
    pub description: String,
    pub operations: Vec<Value>,
}

impl Scenario {
    /// The scenario's identity, `category/name` ([`ScenarioKey`]) — the key
    /// every adjudication names it by.
    pub fn key(&self) -> ScenarioKey {
        ScenarioKey::of(&self.category, &self.name)
    }
}

/// Why the vendored golden tree did not load.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoadError {
    /// A directory of the tree, or one of its entries, could not be read.
    ReadDir { path: PathBuf, source: io::Error },
    /// A golden file could not be read.
    Read { path: PathBuf, source: io::Error },
    /// A golden file is not JSON.
    Parse { path: PathBuf, source: serde_json::Error },
    /// A golden file carries no `operations` array.
    NoOperations { path: PathBuf },
    /// Two goldens share one key, which no adjudication could tell apart.
    DuplicateKey(ScenarioKey),
    /// A file the sweep would never play: a golden outside every category,
    /// or anything in a category that is no golden — a nested directory, a
    /// `.json.orig`, a `.JSON`.
    Stray { path: PathBuf },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::ReadDir { path, .. } => write!(f, "cannot list {}", path.display()),
            LoadError::Read { path, .. } => write!(f, "cannot read {}", path.display()),
            LoadError::Parse { path, .. } => write!(f, "{} is not JSON", path.display()),
            LoadError::NoOperations { path } => {
                write!(f, "{} has no operations array", path.display())
            }
            LoadError::DuplicateKey(key) => {
                write!(f, "two golden scenarios share the key {key}")
            }
            LoadError::Stray { path } => {
                write!(f, "{} lies in the golden tree where no sweep plays it", path.display())
            }
        }
    }
}

impl Error for LoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LoadError::ReadDir { source, .. } | LoadError::Read { source, .. } => Some(source),
            LoadError::Parse { source, .. } => Some(source),
            LoadError::NoOperations { .. }
            | LoadError::DuplicateKey(_)
            | LoadError::Stray { .. } => None,
        }
    }
}

/// The entries of directory `dir`, sorted by file name. An entry the
/// directory cannot yield is an error, never skipped: a golden it hid would
/// be a scenario no sweep plays.
fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let unreadable = |source| LoadError::ReadDir { path: dir.to_path_buf(), source };
    let mut paths = fs::read_dir(dir)
        .map_err(unreadable)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<Vec<PathBuf>, io::Error>>()
        .map_err(unreadable)?;
    paths.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    Ok(paths)
}

/// Is `path` a golden's file name: `<name>.json`, exactly?
fn is_golden_file(path: &Path) -> bool {
    path.extension().is_some_and(|x| x == "json")
}

/// Load every scenario, sorted by (category, file name) for a deterministic
/// run order and report. The tree holds category directories and, beside
/// them, its own documentation (MANIFEST-NEW.md); a category holds goldens
/// and nothing else but OS clutter (a dot-file such as `.DS_Store`). JSON
/// beside the categories, or anything in one that is no golden, is a file
/// the sweep would never play, and is refused ([`LoadError::Stray`]); so
/// are two scenarios with one key.
pub fn load_all(golden_dir: &Path) -> Result<Vec<Scenario>, LoadError> {
    let mut out = Vec::new();
    let mut categories = Vec::new();
    for entry in sorted_entries(golden_dir)? {
        let json = entry.extension().is_some_and(|x| x.eq_ignore_ascii_case("json"));
        if entry.is_dir() {
            categories.push(entry);
        } else if json {
            return Err(LoadError::Stray { path: entry });
        }
    }
    for cat in categories {
        let category =
            cat.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        for path in sorted_entries(&cat)? {
            let dot_file = path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.'));
            if dot_file {
                continue;
            }
            if path.is_dir() || !is_golden_file(&path) {
                return Err(LoadError::Stray { path });
            }
            let raw = fs::read_to_string(&path)
                .map_err(|source| LoadError::Read { path: path.clone(), source })?;
            let v: Value = serde_json::from_str(&raw)
                .map_err(|source| LoadError::Parse { path: path.clone(), source })?;
            let name = v
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
                });
            let description = v
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let operations = v
                .get("operations")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| LoadError::NoOperations { path: path.clone() })?;
            out.push(Scenario { category: category.clone(), name, description, operations });
        }
    }
    let mut keys = BTreeSet::new();
    for s in &out {
        if !keys.insert(s.key()) {
            return Err(LoadError::DuplicateKey(s.key()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scenario is adjudicated by its key, so two scenarios with one key
    /// — two files in one category recording the same name — are refused,
    /// while one name in two categories is two scenarios.
    #[test]
    fn two_scenarios_with_one_key_are_refused() {
        let scratch = format!("skep-conformance-keys-{}", std::process::id());
        let root = std::env::temp_dir().join(scratch);
        let golden = root.join("golden");
        let write = |cat: &str, file: &str| {
            fs::create_dir_all(golden.join(cat)).expect("a category directory");
            let body = r#"{"name": "same", "operations": []}"#;
            fs::write(golden.join(cat).join(file), body).expect("a golden file");
        };
        write("discovery", "a.json");
        write("identity", "a.json");
        let loaded = load_all(&golden).expect("one name in two categories");
        let keys: Vec<String> = loaded.iter().map(|s| s.key().to_string()).collect();
        assert_eq!(keys, ["discovery/same", "identity/same"]);
        write("identity", "b.json");
        let refused = load_all(&golden).err();
        fs::remove_dir_all(&root).expect("the scratch tree is removed");
        assert!(
            matches!(&refused, Some(LoadError::DuplicateKey(k)) if k.as_str() == "identity/same"),
            "{refused:?}"
        );
    }

    /// A golden that is not JSON, or carries no operations, is the vendoring
    /// broken: refused by its path, never skipped.
    #[test]
    fn a_golden_that_does_not_read_is_refused() {
        let scratch = format!("skep-conformance-unread-{}", std::process::id());
        let root = std::env::temp_dir().join(scratch);
        let file = root.join("golden").join("cat").join("a.json");
        fs::create_dir_all(root.join("golden").join("cat")).expect("a category directory");
        fs::write(&file, "{not json").expect("a golden file");
        let unparsed = load_all(&root.join("golden")).err();
        fs::write(&file, r#"{"name": "a"}"#).expect("a golden file");
        let opless = load_all(&root.join("golden")).err();
        fs::remove_dir_all(&root).expect("the scratch tree is removed");
        assert!(
            matches!(&unparsed, Some(LoadError::Parse { path, .. }) if *path == file),
            "{unparsed:?}"
        );
        assert!(
            matches!(&opless, Some(LoadError::NoOperations { path }) if *path == file),
            "{opless:?}"
        );
    }

    /// A golden the sweep would never play — outside every category, in a
    /// directory nested in one, under a name no golden carries — is refused
    /// by its path, never skipped; the tree's own documentation beside the
    /// categories, and OS clutter in one, load.
    #[test]
    fn a_golden_the_sweep_would_not_play_is_refused() {
        let scratch = format!("skep-conformance-stray-{}", std::process::id());
        let root = std::env::temp_dir().join(scratch);
        let golden = root.join("golden");
        fs::create_dir_all(golden.join("cat")).expect("a category directory");
        let body = r#"{"name": "a", "operations": []}"#;
        fs::write(golden.join("cat").join("a.json"), body).expect("a golden file");
        fs::write(golden.join("README.md"), "the tree's notes").expect("documentation");
        fs::write(golden.join("cat").join(".DS_Store"), "clutter").expect("clutter");
        let clean = load_all(&golden).map(|scenarios| scenarios.len());
        let stray = |path: PathBuf, make: &dyn Fn(&Path)| {
            make(&path);
            let refused = load_all(&golden).err();
            if path.is_dir() {
                fs::remove_dir_all(&path).expect("the stray directory is removed");
            } else {
                fs::remove_file(&path).expect("the stray file is removed");
            }
            matches!(refused, Some(LoadError::Stray { path: p }) if p == path)
        };
        let file = |p: &Path| fs::write(p, body).expect("a stray file");
        let outside = stray(golden.join("x.json"), &file);
        let nested = stray(golden.join("cat").join("sub"), &|p| {
            fs::create_dir_all(p).expect("a nested directory")
        });
        let misnamed = stray(golden.join("cat").join("a.json.orig"), &file);
        let shouted = stray(golden.join("cat").join("b.JSON"), &file);
        fs::remove_dir_all(&root).expect("the scratch tree is removed");
        assert_eq!(clean.ok(), Some(1));
        let refused = [outside, nested, misnamed, shouted];
        assert_eq!(refused, [true; 4], "outside, nested, misnamed, shouted");
    }
}
