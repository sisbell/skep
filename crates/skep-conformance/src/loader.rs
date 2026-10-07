//! Scenario loading: walk `conformance/golden/<category>/<name>.json`, parse
//! each file as dynamic JSON (`{ name, description, operations: [...] }`
//! where every operation is a loose field-bag). Parse failures are hard
//! loader errors — the goldens are vendored data; a file that does not parse
//! means the vendoring broke, not the systems, and so are two scenarios
//! sharing one key ([`Scenario::key`]), which no adjudication could tell
//! apart. [`conformance_dir`] locates the vendored tree the goldens and the
//! allowlist live in.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::outcome::scenario_key;

/// `skep/conformance/` located from this crate — the golden tree and the
/// allowlist live here.
pub fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

pub struct Scenario {
    pub category: String,
    pub name: String,
    pub description: String,
    pub operations: Vec<Value>,
}

impl Scenario {
    /// The scenario's identity, `category/name` ([`scenario_key`]) — the key
    /// every adjudication names it by.
    pub fn key(&self) -> String {
        scenario_key(&self.category, &self.name)
    }
}

/// Load every scenario, sorted by (category, file name) for a deterministic
/// run order and report. Two scenarios with one key are refused.
pub fn load_all(golden_dir: &Path) -> Result<Vec<Scenario>, String> {
    let mut out = Vec::new();
    let mut cats: Vec<_> = fs::read_dir(golden_dir)
        .map_err(|e| format!("golden dir {}: {e}", golden_dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    cats.sort_by_key(|e| e.file_name());
    for cat in cats {
        let category = cat.file_name().to_string_lossy().into_owned();
        let mut files: Vec<_> = fs::read_dir(cat.path())
            .map_err(|e| format!("category {}: {e}", category))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort_by_key(|e| e.file_name());
        for f in files {
            let path = f.path();
            let raw = fs::read_to_string(&path)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            let v: Value = serde_json::from_str(&raw)
                .map_err(|e| format!("parse {}: {e}", path.display()))?;
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
                .ok_or_else(|| format!("{}: no operations array", path.display()))?;
            out.push(Scenario { category: category.clone(), name, description, operations });
        }
    }
    let mut keys = BTreeSet::new();
    for s in &out {
        if !keys.insert(s.key()) {
            return Err(format!("two golden scenarios share the key {}", s.key()));
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
        let keys: Vec<String> = loaded.iter().map(Scenario::key).collect();
        assert_eq!(keys, ["discovery/same", "identity/same"]);
        write("identity", "b.json");
        let refused = load_all(&golden).err();
        fs::remove_dir_all(&root).expect("the scratch tree is removed");
        assert_eq!(refused.as_deref(), Some("two golden scenarios share the key identity/same"));
    }
}
