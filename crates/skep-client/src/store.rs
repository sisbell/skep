//! The key store (`client.md` §3): the `KeyStore` seam (§1.4) — `generate`,
//! `signer`, `bindings`, `bind` — and its `FileStore` arm, plain files with
//! modes (§3a's rung 1, RULED): `<store>/keys/<fingerprint>.key` written
//! ONCE under `O_EXCL` at mode `0600` in a `0700` directory (§3.3), the
//! append-only `bindings` file in its TWO line forms (§3.5) under the
//! advisory lock `<store>/lock` (§3.7), and NO anchor under the store, ever
//! (§3.4; AUTH-5.54 step 3). The refusals are the store's own faces
//! ([`KeyFileError`]), never wire tokens, each rendered as AUTH-5.67's halt
//! naming the path and the state.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use skep_identity::{Fingerprint, PublicKey};

use crate::origin::Origin;
use crate::sheet::{KeyFile, Seed};
use crate::sign::{fresh_seed, Signer};

#[cfg(test)]
mod tests;

/// A byline in AUTH-1.24's DOMAIN, never empty (AUTH-5.42): non-empty, no
/// `\n`, at most 128 BYTES of UTF-8 counted as `Enrollment::new` counts.
/// Every box applies the domain test ITSELF, before anything is made from a
/// label (P13; `client.md` §2.2 `keygen`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label(String);

/// Why a label is outside the domain — faced at the box, with the byte
/// count named where the limit is the fault (AUTH-1.25's `TooLong` and
/// `Newline`, and the empty label AUTH-5.42 faces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelFault {
    Empty,
    Newline,
    TooLong { bytes: usize },
}

impl fmt::Display for LabelFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelFault::Empty => f.write_str("the label is empty — a name is required here"),
            LabelFault::Newline => f.write_str("the label holds a line break, which a label cannot"),
            LabelFault::TooLong { bytes } => write!(
                f,
                "the label is {bytes} bytes of UTF-8 and the limit is 128 bytes — counted in bytes, not characters"
            ),
        }
    }
}

impl Label {
    /// The domain test (AUTH-1.24), the newline read before the length as
    /// `Enrollment::new` reads it (AUTH-1.25).
    pub fn new(text: &str) -> Result<Label, LabelFault> {
        if text.contains('\n') {
            return Err(LabelFault::Newline);
        }
        if text.len() > 128 {
            return Err(LabelFault::TooLong { bytes: text.len() });
        }
        if text.is_empty() {
            return Err(LabelFault::Empty);
        }
        Ok(Label(text.to_string()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The label as a path component: ASCII alphanumerics kept, every other
    /// character a `-`, runs collapsed — the slug the anchor file's name
    /// takes (§6).
    pub fn slug(&self) -> String {
        let mut out = String::new();
        let mut dash = false;
        for c in self.0.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_lowercase());
                dash = false;
            } else if !dash {
                out.push('-');
                dash = true;
            }
        }
        let trimmed = out.trim_matches('-').to_string();
        if trimmed.is_empty() { "key".to_string() } else { trimmed }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A key's identity in the store — its FINGERPRINT, the file's name (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub Fingerprint);

/// §3.5's lookup input (§1.4): a key-file path, the (`--board`,
/// `--principal`) pair the binding and lone-key arms take, or `fingerprint
/// --select`'s prefix-or-label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySelector<'a> {
    /// `--key <path>` / `SKEP_KEY`: that file, no lookup (arm 1).
    Path(&'a Path),
    /// A binding for (origin, principal) — arms 2 and 3; `None` for the
    /// principal where the board has exactly one binding in the store.
    Binding { origin: &'a Origin, principal: Option<u64> },
    /// A fingerprint prefix, 2–64 characters of `[0-9a-f]`.
    Prefix(&'a str),
    /// A label — not unique by rule (AUTH-5.3).
    Label(&'a str),
}

impl<'a> KeySelector<'a> {
    /// `fingerprint --select`'s two arms told apart by SHAPE: 2–64
    /// characters all in `[0-9a-f]` is a prefix, anything else a label.
    pub fn select(text: &'a str) -> KeySelector<'a> {
        let hexy = (2..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if hexy { KeySelector::Prefix(text) } else { KeySelector::Label(text) }
    }
}

/// What a selected key is to be used for: SIGNING (or enrolment as a device
/// key), where an anchor file is REFUSED whichever arm selected it (§2.2's
/// selection test, P11); or a READ of its public facts (`fingerprint
/// --key`, `verify`), where it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Sign,
    Read,
}

/// ONE LINE of the bindings file, IN EITHER OF ITS TWO FORMS AND NO THIRD
/// (§3.5): the enrolment line `origin principal account fingerprint`
/// (AUTH-5.76's retention), and the `signed <dialed-origin> <signed-origin>`
/// line a frontend at its own bind-override node writes (AUTH-4.57 (a)'s
/// client half). The two are told apart by the first field — a canonical
/// origin carries `://`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Enrolment { origin: Origin, principal: u64, account: String, fingerprint: Fingerprint },
    Signed { dialed: Origin, signed: Origin },
}

impl Binding {
    /// The line, without its newline.
    pub fn line(&self) -> String {
        match self {
            Binding::Enrolment { origin, principal, account, fingerprint } => {
                format!("{origin} {principal} {account} {fingerprint}")
            }
            Binding::Signed { dialed, signed } => format!("signed {dialed} {signed}"),
        }
    }

    /// One line parsed, `None` for a line of neither form (a hand-edited
    /// stray, ignored as a torn final line is).
    pub fn parse_line(line: &str) -> Option<Binding> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["signed", dialed, signed] => Some(Binding::Signed { dialed: Origin::parse(dialed)?, signed: Origin::parse(signed)? }),
            [origin, principal, account, fingerprint] if origin.contains("://") => Some(Binding::Enrolment {
                origin: Origin::parse(origin)?,
                principal: principal.parse().ok()?,
                account: account.to_string(),
                fingerprint: Fingerprint::parse_hex(fingerprint)?,
            }),
            _ => None,
        }
    }
}

/// THE STORE'S OWN REFUSALS (§3.2), faces and never wire tokens, each
/// read off the FILE's own contents — a state, rendered as AUTH-5.67's halt
/// naming the path and the state; all exit 3 (§1.1's `halt` row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFileError {
    /// Not JSON, or `type` is not `skep-key`.
    NotKeyFile,
    /// `v` above 1: "this file was written by a newer skep than this one",
    /// never "not a key file".
    Newer { v: u64 },
    /// A member missing, of the wrong type, out of its domain, or unknown.
    Schema { member: String },
    /// `public` or `fingerprint` does not re-derive from the seed: "this is
    /// not the key this file names" (AUTH-5.39).
    Disagrees,
    /// An anchor file where a key was selected to SIGN or to be enrolled as a
    /// device key (§2.2's selection test): the one walk that imports an
    /// anchor is `skep recover`.
    AnchorAtSigningCommand,
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::NotKeyFile => f.write_str("this is not a skep key file"),
            KeyFileError::Newer { v } => write!(f, "this file was written by a newer skep than this one (v {v})"),
            KeyFileError::Schema { member } => write!(f, "the file's `{member}` member is missing, of the wrong type or outside its domain"),
            KeyFileError::Disagrees => f.write_str("this is not the key this file names: its public key and fingerprint do not re-derive from its seed"),
            KeyFileError::AnchorAtSigningCommand => f.write_str(
                "this is an ANCHOR's file, and an anchor is refused wherever a key is selected to sign or to be \
                 enrolled as a device key — the one walk that imports an anchor is `skep recover`",
            ),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// The public facts of one key in the store — what `fingerprint --dir`
/// lists and what a lookup's halt names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFacts {
    pub path: PathBuf,
    pub alg: String,
    pub fingerprint: Fingerprint,
    pub public: PublicKey,
    pub label: Option<String>,
    pub anchor: bool,
}

/// What the store could not do.
#[derive(Debug)]
pub enum StoreError {
    /// A key file refused by its own contents (AUTH-5.67's halt names the
    /// path and the state).
    KeyFile { path: PathBuf, error: KeyFileError },
    /// A path missing, unreadable or mis-pathed — HALT AND SURFACE naming
    /// it, never a fallback (AUTH-5.67).
    Io { path: PathBuf, error: io::Error },
    /// A binding's fingerprint names no file in the store.
    MissingKey { path: PathBuf, fingerprint: Fingerprint },
    /// §3.5 arm 4: no key was selected — the store's keys listed for the
    /// caller to fork the face on `claimant`.
    NoSelection { keys: Vec<KeyFacts> },
    /// More than one key matches a `--select` — every match listed, never a
    /// pick (`client.md` §2.2).
    Ambiguous { keys: Vec<KeyFacts> },
    /// No key matches a `--select`.
    NotFound { select: String },
    /// The bindings file could not be appended — a read-only mount; a
    /// WARNING, never a refusal: the line, for the person to record (§3.7).
    ReadOnly { path: PathBuf, line: String, error: io::Error },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::KeyFile { path, error } => write!(f, "{}: {error}", path.display()),
            StoreError::Io { path, error } => write!(f, "{}: {error}", path.display()),
            StoreError::MissingKey { path, fingerprint } => {
                write!(f, "{}: the bindings name key {fingerprint} and the store holds no file for it", path.display())
            }
            StoreError::NoSelection { keys } => write!(f, "no key selected ({} in the store)", keys.len()),
            StoreError::Ambiguous { keys } => write!(f, "{} keys match", keys.len()),
            StoreError::NotFound { select } => write!(f, "no key in the store matches `{select}`"),
            StoreError::ReadOnly { path, line, error } => {
                write!(f, "{}: could not append ({error}); record this line yourself: {line}", path.display())
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// THE SEAM (§1.4): rung 2's `generate` mints the keychain item the file
/// then indexes, which no `Signer` can do — the trait's one non-signing job
/// and its warrant (§9 item 26). `generate` takes no anchor flag: an anchor
/// is generated by the ceremony's own in-memory signer and exported, never
/// through the store (§3.4).
pub trait KeyStore {
    /// One DEVICE key of the production kind from a fresh OS seed, its file
    /// written once; the fingerprint names it.
    fn generate(&self, label: Option<Label>) -> Result<KeyId, StoreError>;
    /// The signer `sel` names, an anchor refused (§2.2's selection test).
    fn signer(&self, sel: &KeySelector<'_>) -> Result<Box<dyn Signer>, StoreError>;
    /// Every binding line for `origin`, in file order (the newest last).
    fn bindings(&self, origin: &Origin) -> Result<Vec<Binding>, StoreError>;
    /// Append one line under the lock.
    fn bind(&self, b: &Binding) -> Result<(), StoreError>;
}

/// The default store on every platform: `~/.skep/` (§6; §9 item 10, RULED —
/// the ssh convention; the user profile's `.skep` on Windows).
pub fn default_store_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| PathBuf::from(home).join(".skep"))
}

/// A key selected by the lookup: its file and its path.
pub struct Selected {
    pub path: PathBuf,
    pub file: KeyFile,
}

/// Rung 1: plain files with modes (§3.1–§3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// The store at `root`; nothing is created until a write.
    pub fn open(root: impl Into<PathBuf>) -> FileStore {
        FileStore { root: root.into() }
    }

    /// The store's directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    fn bindings_path(&self) -> PathBuf {
        self.root.join("bindings")
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join("lock")
    }

    /// The path a key of `fp` rests at.
    pub fn key_path(&self, fp: &Fingerprint) -> PathBuf {
        self.keys_dir().join(format!("{}.key", fp.to_hex()))
    }

    /// §3.4's check: whether `path` lies under this store — where an anchor
    /// file is REFUSED (the backup moment's destination; a later `--anchor`).
    pub fn contains_path(&self, path: &Path) -> bool {
        let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let root = canon(&self.root);
        let target = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => match path.parent() {
                Some(parent) if parent.as_os_str().is_empty() => canon(Path::new(".")).join(path),
                Some(parent) => canon(parent).join(path.file_name().unwrap_or_default()),
                None => path.to_path_buf(),
            },
        };
        target.starts_with(&root)
    }

    /// The directory `0700`, created once (§3.3); the umask irrelevant.
    fn ensure_dirs(&self) -> Result<(), StoreError> {
        for dir in [self.root.clone(), self.keys_dir()] {
            if dir.is_dir() {
                continue;
            }
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&dir).map_err(|error| StoreError::Io { path: dir.clone(), error })?;
        }
        Ok(())
    }

    /// A file written ONCE: `O_CREAT|O_EXCL`, mode `0600` set at creation
    /// (§3.3) — never chmod'd after a world-readable moment. The one writer
    /// every key file and anchor file of this crate goes through.
    pub fn write_once(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    /// One key file loaded and judged (§3.2's reader; AUTH-5.67's halt names
    /// the path).
    pub fn load(&self, path: &Path) -> Result<KeyFile, StoreError> {
        let bytes = fs::read(path).map_err(|error| StoreError::Io { path: path.to_path_buf(), error })?;
        KeyFile::parse(&bytes).map_err(|error| StoreError::KeyFile { path: path.to_path_buf(), error })
    }

    /// Every key file in the store, by file name order, its public facts.
    pub fn list(&self) -> Result<Vec<KeyFacts>, StoreError> {
        let dir = self.keys_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(StoreError::Io { path: dir, error }),
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "key"))
            .collect();
        paths.sort();
        paths.iter().map(|p| self.facts_of(p)).collect()
    }

    fn facts_of(&self, path: &Path) -> Result<KeyFacts, StoreError> {
        let file = self.load(path)?;
        Ok(KeyFacts {
            path: path.to_path_buf(),
            alg: file.alg.clone(),
            fingerprint: file.fingerprint,
            public: file.public.clone(),
            label: file.label.clone(),
            anchor: file.anchor,
        })
    }

    /// Whether the store holds a key file for `fp`.
    pub fn holds(&self, fp: &Fingerprint) -> bool {
        self.key_path(fp).is_file()
    }

    /// Every binding line, in file order; a final line without `\n` ignored
    /// (§3.7: a torn append is never a torn record).
    pub fn all_bindings(&self) -> Result<Vec<Binding>, StoreError> {
        let path = self.bindings_path();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(StoreError::Io { path, error }),
        };
        let complete = match text.rfind('\n') {
            Some(i) => &text[..=i],
            None => "",
        };
        Ok(complete.lines().filter_map(Binding::parse_line).collect())
    }

    /// The LAST enrolment line for (`origin`, `principal`) — the newest
    /// wins (§3.5 arm 2).
    pub fn enrolment_for(&self, origin: &Origin, principal: u64) -> Result<Option<(String, Fingerprint)>, StoreError> {
        Ok(self.all_bindings()?.into_iter().rev().find_map(|b| match b {
            Binding::Enrolment { origin: o, principal: p, account, fingerprint } if &o == origin && p == principal => {
                Some((account, fingerprint))
            }
            _ => None,
        }))
    }

    /// The principals bound at `origin`, newest first, each once — the
    /// "exactly one binding" test that lets `--principal` be omitted.
    pub fn principals_at(&self, origin: &Origin) -> Result<Vec<u64>, StoreError> {
        let mut out: Vec<u64> = Vec::new();
        for b in self.all_bindings()?.into_iter().rev() {
            if let Binding::Enrolment { origin: o, principal, .. } = b {
                if &o == origin && !out.contains(&principal) {
                    out.push(principal);
                }
            }
        }
        Ok(out)
    }

    /// The `signed` line's origin for `dialed`, where one stands (§3.5).
    pub fn signed_origin_for(&self, dialed: &Origin) -> Result<Option<Origin>, StoreError> {
        Ok(self.all_bindings()?.into_iter().rev().find_map(|b| match b {
            Binding::Signed { dialed: d, signed } if &d == dialed => Some(signed),
            _ => None,
        }))
    }

    /// THE LOOKUP (§3.5), in its precedence: (1) a path; (2) the LAST
    /// binding for (origin, principal); (3) no binding and exactly one
    /// device key in the store; (4) otherwise `NoSelection` with the keys
    /// listed, for the caller's fork on `claimant`. Under `Purpose::Sign`
    /// an anchor file is refused at every arm (§2.2's selection test).
    pub fn select(&self, sel: &KeySelector<'_>, purpose: Purpose) -> Result<Selected, StoreError> {
        let judged = |path: PathBuf| -> Result<Selected, StoreError> {
            let file = self.load(&path)?;
            if purpose == Purpose::Sign && file.anchor {
                return Err(StoreError::KeyFile { path, error: KeyFileError::AnchorAtSigningCommand });
            }
            Ok(Selected { path, file })
        };
        match sel {
            KeySelector::Path(path) => judged(path.to_path_buf()),
            KeySelector::Binding { origin, principal } => {
                let principal = match principal {
                    Some(p) => Some(*p),
                    None => {
                        let ps = self.principals_at(origin)?;
                        if ps.len() == 1 { Some(ps[0]) } else { None }
                    }
                };
                if let Some(p) = principal {
                    if let Some((_, fp)) = self.enrolment_for(origin, p)? {
                        let path = self.key_path(&fp);
                        if !path.is_file() {
                            return Err(StoreError::MissingKey { path, fingerprint: fp });
                        }
                        return judged(path);
                    }
                }
                let keys = self.list()?;
                let devices: Vec<&KeyFacts> = keys.iter().filter(|k| !k.anchor).collect();
                if devices.len() == 1 {
                    return judged(devices[0].path.clone());
                }
                Err(StoreError::NoSelection { keys })
            }
            KeySelector::Prefix(prefix) => {
                let keys = self.list()?;
                let matches: Vec<&KeyFacts> = keys.iter().filter(|k| k.fingerprint.to_hex().starts_with(prefix)).collect();
                self.one_of(matches, &keys, prefix, purpose)
            }
            KeySelector::Label(label) => {
                let keys = self.list()?;
                let matches: Vec<&KeyFacts> = keys.iter().filter(|k| k.label.as_deref() == Some(*label)).collect();
                self.one_of(matches, &keys, label, purpose)
            }
        }
    }

    fn one_of(&self, matches: Vec<&KeyFacts>, _all: &[KeyFacts], select: &str, purpose: Purpose) -> Result<Selected, StoreError> {
        match matches.as_slice() {
            [] => Err(StoreError::NotFound { select: select.to_string() }),
            [one] => {
                let file = self.load(&one.path)?;
                if purpose == Purpose::Sign && file.anchor {
                    return Err(StoreError::KeyFile { path: one.path.clone(), error: KeyFileError::AnchorAtSigningCommand });
                }
                Ok(Selected { path: one.path.clone(), file })
            }
            many => Err(StoreError::Ambiguous { keys: many.iter().map(|k| (*k).clone()).collect() }),
        }
    }

    /// Append `line` to the bindings file in ONE `write` under the advisory
    /// lock on `<store>/lock` (§3.7). A failed append — a read-only mount —
    /// is `ReadOnly`, carrying the line for the person to record.
    pub fn append_line(&self, line: &str) -> Result<(), StoreError> {
        let path = self.bindings_path();
        let text = format!("{line}\n");
        let read_only = |error: io::Error| StoreError::ReadOnly { path: path.clone(), line: line.to_string(), error };
        self.ensure_dirs().map_err(|e| match e {
            StoreError::Io { error, .. } => read_only(error),
            other => other,
        })?;
        let mut lock_opts = OpenOptions::new();
        lock_opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_opts.mode(0o600);
        }
        let lock = lock_opts.open(self.lock_path()).map_err(read_only)?;
        lock.lock().map_err(read_only)?;
        let result = (|| -> io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.append(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&path)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })();
        let _ = lock.unlock();
        result.map_err(read_only)
    }
}

impl KeyStore for FileStore {
    fn generate(&self, label: Option<Label>) -> Result<KeyId, StoreError> {
        self.ensure_dirs()?;
        let file = KeyFile::new(Seed::new(fresh_seed()), false, label.map(|l| l.0), None);
        let path = self.key_path(&file.fingerprint);
        Self::write_once(&path, file.to_json().as_bytes()).map_err(|error| StoreError::Io { path, error })?;
        Ok(KeyId(file.fingerprint))
    }

    fn signer(&self, sel: &KeySelector<'_>) -> Result<Box<dyn Signer>, StoreError> {
        let selected = self.select(sel, Purpose::Sign)?;
        Ok(Box::new(selected.file.signer()))
    }

    fn bindings(&self, origin: &Origin) -> Result<Vec<Binding>, StoreError> {
        Ok(self
            .all_bindings()?
            .into_iter()
            .filter(|b| match b {
                Binding::Enrolment { origin: o, .. } => o == origin,
                Binding::Signed { dialed, .. } => dialed == origin,
            })
            .collect())
    }

    fn bind(&self, b: &Binding) -> Result<(), StoreError> {
        self.append_line(&b.line())
    }
}
