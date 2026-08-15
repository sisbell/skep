//! Scenario loading: walk `conformance/golden/<category>/<name>.json`, parse
//! each file as dynamic JSON (`{ name, description, operations: [...] }`
//! where every operation is a loose field-bag). Parse failures are hard
//! loader errors — the goldens are vendored data; a file that does not parse
//! means the vendoring broke, not the systems.

use std::fs;
use std::path::Path;

use serde_json::Value;

pub struct Scenario {
    pub category: String,
    pub name: String,
    pub description: String,
    pub operations: Vec<Value>,
}

/// Load every scenario, sorted by (category, file name) for a deterministic
/// run order and report.
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
    Ok(out)
}
