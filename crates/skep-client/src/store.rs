//! The key store (`client.md` §3): the `KeyStore` seam (§1.4) — `generate`,
//! `signer`, `bindings`, `bind` — and its `FileStore` arm, plain files with
//! modes (§3a's rung 1, RULED): `<store>/keys/<fingerprint>.key` written
//! ONCE under `O_EXCL` at mode `0600` in a `0700` directory (§3.3), the
//! append-only `bindings` file in its TWO line forms (§3.5) under the
//! advisory lock `<store>/lock` (§3.7), and NO anchor under the store, ever
//! (§3.4; AUTH-5.54 step 3). The refusals are the store's own faces
//! ([`StoreError`], [`KeyFileError`]), never wire tokens, each rendered by
//! [`store_halt`] as AUTH-5.67's halt naming the path and the state; a
//! lookup that selects no key is §3.5 arm 4's fork, [`arm4_face`].

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use skep_identity::{Fingerprint, PublicKey};

use crate::address::first_child;
use crate::derive::Mode;
use crate::halt::Halt;
use crate::origin::Origin;
use crate::sheet::{render_inert, KeyFile, KeyFileError, Seed};
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

/// What a selected key is to be used for: SIGNING (or enrollment as a device
/// key), where an anchor file is REFUSED whichever arm selected it (§2.2's
/// selection test, P11); or a READ of its public facts (`fingerprint
/// --key`, `verify`), where it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Sign,
    Read,
}

/// ONE LINE of the bindings file, IN EITHER OF ITS TWO FORMS AND NO THIRD
/// (§3.5): the enrollment line `origin principal account fingerprint`
/// (AUTH-5.76's retention), and the `signed <dialed-origin> <signed-origin>`
/// line a frontend at its own bind-override node writes (AUTH-4.57 (a)'s
/// client half). The two are told apart by the first field — a canonical
/// origin carries `://`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Enrollment { origin: Origin, principal: u64, account: String, fingerprint: Fingerprint },
    Signed { dialed: Origin, signed: Origin },
}

impl Binding {
    /// The line, without its newline.
    pub fn line(&self) -> String {
        match self {
            Binding::Enrollment { origin, principal, account, fingerprint } => {
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
            [origin, principal, account, fingerprint] if origin.contains("://") => Some(Binding::Enrollment {
                origin: Origin::parse(origin)?,
                principal: principal.parse().ok()?,
                account: account.to_string(),
                fingerprint: Fingerprint::parse_hex(fingerprint)?,
            }),
            _ => None,
        }
    }
}

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

/// A store refusal as AUTH-5.67's halt naming the path and the state.
pub fn store_halt(e: StoreError) -> Halt {
    match e {
        StoreError::KeyFile { path, error } => Halt::face(
            format!("the key file {} is refused: {error}", path.display()),
            "the file's own contents decide this (client.md §3.2)",
            match error {
                KeyFileError::AnchorAtSigningCommand => "select a device key; the one walk that imports an anchor is `skep recover`",
                KeyFileError::Newer { .. } => "upgrade skep, or select a key this version wrote",
                _ => "point `--key` at a key file `skep keygen` wrote, or run `skep keygen`",
            },
        ),
        StoreError::Io { path, error } => Halt::face(
            format!("the key file {} is missing, unreadable or mis-pathed: {error}", path.display()),
            "AUTH-5.67: a key file missing, unreadable or mis-pathed is HALT AND SURFACE, never a fallback to a bare bind",
            "check the path (`--key`, `SKEP_KEY`, `--dir`)",
        ),
        StoreError::MissingKey { path, fingerprint } => Halt::face(
            format!("the bindings name key {fingerprint} and the store holds no file at {}", path.display()),
            "the key file was removed from the store after the binding was written",
            "restore the file, or re-run the hop that binds another key",
        ),
        other => Halt::face("the key store refused", other.to_string(), "see the store's state above"),
    }
}

/// §3.5 arm 4's three forks on `claimant`.
pub fn arm4_face(store: &FileStore, keys: &[KeyFacts], mode: Mode, local_trust: bool) -> Halt {
    match (mode, keys.is_empty()) {
        (Mode::Unclaimed, true) => Halt::face(
            format!("the key store {} holds no key, and this board is unclaimed", store.root().display()),
            "`skep claim` generates no device key: the notebook door is two commands",
            "run `skep keygen` first, then `skep claim` again",
        ),
        (_, false) => {
            let list: Vec<String> = keys.iter().map(|k| format!("{} {}", k.fingerprint, k.label.as_deref().map(render_inert).unwrap_or_default())).collect();
            Halt::face(
                "more than one key is in this store and none is bound to this board and principal",
                format!("the store holds:\n  {}", list.join("\n  ")),
                "name the key with `--key <path>` (`skep fingerprint --dir` lists them); never a pick",
            )
        }
        (_, true) => {
            let residue = if local_trust {
                "in CLAIMED-PERMISSIVE bare sessions still open on loopback and still write drafts, so that board is DRAFT-ONLY FOREVER: every draft stays readable and writable, and material can be carried across by re-authoring before a fresh board is minted"
            } else {
                "in ENFORCING it is READ-ONLY FOREVER"
            };
            Halt::face(
                format!("the key store {} is keyless for this claimed board", store.root().display()),
                "a wiped profile, a lost store, or a second machine (AUTH-5.32)",
                format!(
                    "either: generate a key here and enroll it from a device you are still signed in on (`skep keygen --payload` here, \
                     `skep enroll` there, `skep bind` back here); or import a paper anchor (`skep keygen` here, then `skep recover`, \
                     which enrolls the new key from the anchor's session and retires the lost one). Where NEITHER is available — no \
                     signed-in device and both anchors gone — no \
                     key opens this account and none ever will, and what exists is a fresh board: {residue}; either way total key \
                     loss freezes the mint. And everything this account shared STAYS SHARED: every grant it issued stands forever, \
                     only this account could withdraw it, and the fresh board carries none of it back."
                ),
            )
        }
    }
}

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

    /// The LAST enrollment line for (`origin`, `principal`) — the newest
    /// wins (§3.5 arm 2).
    pub fn enrollment_for(&self, origin: &Origin, principal: u64) -> Result<Option<(String, Fingerprint)>, StoreError> {
        Ok(self.all_bindings()?.into_iter().rev().find_map(|b| match b {
            Binding::Enrollment { origin: o, principal: p, account, fingerprint } if &o == origin && p == principal => {
                Some((account, fingerprint))
            }
            _ => None,
        }))
    }

    /// The principals bound at `origin`, newest first, each once — THE
    /// ONE-BINDING TEST that lets `--principal` be omitted (`client.md`
    /// §3.5, as RULED 2026-10-04: "`--principal` may be omitted where the
    /// board has exactly one binding in the store, the agent space's line
    /// not counting: §4.3's persist-first line binds the account's first
    /// child (`inc(account, 1)`), so a claimed board always holds that line
    /// beside the account's, and the one-binding test excludes every line
    /// whose account is the first child of another line's account at the
    /// same board"). The exclusion is ONE condition: a line is dropped where
    /// its account is [`first_child`] of another line's account at this
    /// origin.
    pub fn principals_at(&self, origin: &Origin) -> Result<Vec<u64>, StoreError> {
        let lines: Vec<(u64, String)> = self
            .all_bindings()?
            .into_iter()
            .filter_map(|b| match b {
                Binding::Enrollment { origin: o, principal, account, .. } if &o == origin => Some((principal, account)),
                _ => None,
            })
            .collect();
        let mut out: Vec<u64> = Vec::new();
        for (principal, account) in lines.iter().rev() {
            let agent_space = lines.iter().any(|(_, other)| first_child(other) == *account);
            if agent_space || out.contains(principal) {
                continue;
            }
            out.push(*principal);
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
                    if let Some((_, fp)) = self.enrollment_for(origin, p)? {
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
                Binding::Enrollment { origin: o, .. } => o == origin,
                Binding::Signed { dialed, .. } => dialed == origin,
            })
            .collect())
    }

    fn bind(&self, b: &Binding) -> Result<(), StoreError> {
        self.append_line(&b.line())
    }
}
