//! THE TEST HOOKS, GATED: every item this crate documents as a test hook or
//! a test seam compiles only under the `test-hooks` feature — the one check
//! of this suite, in the media crate's form
//! (`crates/skep-media/tests/it/tidy.rs`) with its helpers carried here, so
//! each crate's suite stands alone. Two readings the kernel's own shapes
//! need, which that form has not: the `impl` block that holds an item may
//! carry the gate — the kernel's three doors are gated at theirs — and a
//! file whose doc opens with the seam's words is a hook whole, held to its
//! `mod` line's gate — the seam module `src/hooks.rs`, whose items carry no
//! marker of their own. The layering check and the README check that stand
//! beside the hook check in the media crate's suite are not here: `lib.rs`
//! declares the kernel's modules in dependency order and `ARCHITECTURE.md`
//! §The kernel states the rules across them, and the crate's surface is its
//! `README.md`'s prose.

use std::path::{Path, PathBuf};

/// THE TEST HOOKS, GATED: every item this crate documents as a test hook or
/// a test seam — a doc line opening `TEST HOOK`, `TEST SEAM` or `The test
/// seam` — compiles only under the `test-hooks` feature (or `test`), gated
/// on the item itself, on the `impl` block that holds it, or on the `mod`
/// line of the file that holds it; and a file whose doc opens with the
/// seam's words — `//! THE TEST SEAM`, `//! TEST SEAM` or `//! The test
/// seam` — is gated on its `mod` line, whole. `Cargo.toml`'s `test-hooks`
/// card promises "a build that compiles no test compiles none of it". The
/// gate's `--lib` check proves the library COMPILES without the feature,
/// never that no hook ships in it: a hook whose gate is dropped still
/// compiles, and ships, with every other test green. The root must yield a
/// marker, so a crate whose markers were reworded fails here rather than
/// leaving the check unread.
#[test]
fn every_test_hook_compiles_only_under_test_hooks() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = manifest.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut hooks = 0;
    let mut ungated = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let relative = file.strip_prefix(manifest).unwrap().display();
        let file_gated = declared_under_the_gate(&src, &module_of(&src, file));
        // The seam file: its doc opens with the seam's words, and the whole
        // file is the hook its `mod` line gates.
        if lines.first().is_some_and(|line| is_seam_file_doc(line)) {
            hooks += 1;
            if !file_gated {
                ungated.push(format!(
                    "{relative}:1: the file is documented as the test seam and compiles without \
                     `test-hooks`"
                ));
            }
        }
        let end = lines.iter().position(|l| l.trim() == "mod tests {").unwrap_or(lines.len());
        for (i, line) in lines[..end].iter().enumerate() {
            let doc = line.trim_start();
            if !(doc.starts_with("/// TEST HOOK")
                || doc.starts_with("/// TEST SEAM")
                || doc.starts_with("/// The test seam"))
            {
                continue;
            }
            hooks += 1;
            let mut j = i;
            while j < lines.len() && lines[j].trim_start().starts_with("///") {
                j += 1;
            }
            let (attributes, item) = attributes_from(&lines, j);
            if !file_gated
                && !attributes.iter().any(|a| is_gate(a))
                && !enclosing_impl_is_gated(&lines, item)
            {
                ungated.push(format!(
                    "{relative}:{}: `{}` is documented as a test hook and compiles without \
                     `test-hooks`",
                    item + 1,
                    lines.get(item).map_or("", |l| l.trim()),
                ));
            }
        }
    }
    assert!(
        hooks > 0,
        "no test hook found under {}: the markers this check reads have moved",
        src.display()
    );
    assert!(
        ungated.is_empty(),
        "every test hook compiles only under `test-hooks`; these do not:\n{}",
        ungated.join("\n")
    );
}

/// A file's first line opening with the seam's words, as an inner doc: the
/// file is the seam, and the hook is the file.
fn is_seam_file_doc(line: &str) -> bool {
    let doc = line.trim_start();
    doc.starts_with("//! THE TEST SEAM")
        || doc.starts_with("//! TEST SEAM")
        || doc.starts_with("//! The test seam")
}

/// The attributes from `lines[at]` on — each `#[…]`, a multi-line one joined
/// into one — and the index of the line past them: the item they attach to.
fn attributes_from(lines: &[&str], mut at: usize) -> (Vec<String>, usize) {
    let mut attributes = Vec::new();
    while at < lines.len() && lines[at].trim_start().starts_with("#[") {
        let mut attribute = String::new();
        let mut depth = 0i64;
        while at < lines.len() {
            let line = lines[at].trim();
            attribute.push_str(line);
            depth += line.matches('[').count() as i64 - line.matches(']').count() as i64;
            at += 1;
            if depth <= 0 {
                break;
            }
            attribute.push(' ');
        }
        attributes.push(attribute);
    }
    (attributes, at)
}

/// The attributes directly above the item at `lines[item]` — the block
/// walked up to its first `#[` line, a multi-line attribute's continuation
/// lines (which end in `]` and open no attribute of their own) stepped over.
fn attributes_above(lines: &[&str], item: usize) -> Vec<String> {
    let mut start = item;
    while start > 0 {
        let above = lines[start - 1].trim();
        let opens = above.starts_with("#[");
        let continues = above.ends_with(']') && !above.starts_with("//") && !opens;
        if opens || continues {
            start -= 1;
        } else {
            break;
        }
    }
    attributes_from(lines, start).0
}

/// Whether the item at `lines[item]` sits inside an `impl` block whose own
/// attributes carry the gate: the first column-0 line above it is that
/// block's `impl` line, and the attributes above that line are read.
fn enclosing_impl_is_gated(lines: &[&str], item: usize) -> bool {
    if !lines.get(item).is_some_and(|line| line.starts_with(char::is_whitespace)) {
        return false;
    }
    let Some(head) = (0..item)
        .rev()
        .find(|&k| !lines[k].is_empty() && !lines[k].starts_with(char::is_whitespace))
    else {
        return false;
    };
    lines[head].starts_with("impl") && attributes_above(lines, head).iter().any(|a| is_gate(a))
}

/// Whether the `mod` line declaring `module`, in its parent's file, carries
/// the gate among the attributes directly above it — the whole file then
/// compiles only under it.
fn declared_under_the_gate(src: &Path, module: &str) -> bool {
    let (parent, name) = module.rsplit_once("::").unwrap_or(("", module));
    let parent_file = if parent.is_empty() {
        src.join("lib.rs")
    } else {
        let flat = src.join(format!("{}.rs", parent.replace("::", "/")));
        if flat.exists() {
            flat
        } else {
            src.join(parent.replace("::", "/")).join("mod.rs")
        }
    };
    let Ok(text) = std::fs::read_to_string(parent_file) else { return false };
    let lines: Vec<&str> = text.lines().collect();
    let declaration = format!("mod {name};");
    let Some(at) = lines.iter().position(|l| l.trim().ends_with(&declaration)) else {
        return false;
    };
    lines[..at]
        .iter()
        .rev()
        .take_while(|l| l.trim_start().starts_with("#["))
        .any(|l| is_gate(l.trim()))
}

/// A `cfg` attribute that confines what it gates to test builds: the
/// `test-hooks` feature, or `test` itself.
fn is_gate(attribute: &str) -> bool {
    attribute.starts_with("#[cfg(")
        && !attribute.contains("not(")
        && (attribute.contains(r#"feature = "test-hooks""#) || attribute == "#[cfg(test)]")
}

/// `src/kernel.rs` → `kernel`; `src/kernel/history.rs` → `kernel::history`;
/// a `foo/mod.rs` → `foo`.
fn module_of(src: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(src).unwrap().with_extension("");
    let mut segments: Vec<String> =
        relative.iter().map(|s| s.to_string_lossy().into_owned()).collect();
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
