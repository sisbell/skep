//! A scratch directory for the unit suites, removed when dropped.
//!
//! It is made under the system temp directory, named by OS entropy.

use std::path::{Path, PathBuf};

/// One scratch directory.
pub struct Scratch(PathBuf);

impl Scratch {
    /// Returns a fresh one, `0700`.
    ///
    /// # Panics
    ///
    /// Panics where the OS gives no entropy for its name, or where the
    /// directory cannot be made.
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

    /// Returns its path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // A directory a test made unwritable is made writable again first.
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
