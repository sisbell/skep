//! A scratch directory for the unit suites: made under the system temp
//! directory, named by OS entropy, removed when dropped.

use std::path::{Path, PathBuf};

/// One scratch directory.
pub struct Scratch(PathBuf);

impl Scratch {
    /// A fresh one, `0700`.
    pub fn new() -> Scratch {
        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).expect("OS entropy");
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("skep-provision-test-{name}"));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).expect("a scratch directory");
        Scratch(path)
    }

    /// Its path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // A test that made a directory unwritable gives it back first.
            use std::os::unix::fs::PermissionsExt;
            if let Ok(entries) = std::fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o700));
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
