//! The key store (`client.md` §3): the `KeyStore` seam (§1.4) — `generate`,
//! `signer`, `bindings`, `bind` — and its `FileStore` arm, plain files with
//! modes (§3a's rung 1, RULED): `<store>/keys/<fingerprint>.key` written
//! ONCE under `O_EXCL` at mode `0600` in a `0700` directory (§3.3), the
//! append-only `bindings` file in its TWO line forms (§3.5) under the
//! advisory lock `<store>/lock` (§3.7), and NO anchor under the store, ever
//! (§3.4; AUTH-5.54 step 3). The store is the seed's CUSTODIAN (§3a:
//! "signing and key lookup behind `Signer` and `KeyStore`"): a lookup
//! answers a key's PUBLIC facts, [`KeyFacts`], and the seed leaves the store
//! only as the signer [`KeyStore::signer`] derives from it — so a later
//! custody rung is a different signer behind that one method, never a
//! rewrite of a walk (§1.4). The refusals are the store's own faces
//! ([`StoreError`], [`KeyFileError`]), never wire tokens, each converted
//! into AUTH-5.67's halt naming the path and the state by
//! `From<StoreError> for Halt`, so a walk's `?` carries it; a lookup that
//! selects no key is §3.5 arm 4's fork, [`arm4_face`]. A binding line that
//! cannot be appended is no refusal at all: [`Unappended`], the warning
//! carrying the line (§3.7).

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use skep_identity::{Fingerprint, PublicKey};

use crate::address::first_child;
use crate::derive::Mode;
use crate::halt::Halt;
use crate::origin::Origin;
use crate::sheet::{render_inert, KeyFile, KeyFileError, Label, Seed};
use crate::sign::Signer;

#[cfg(test)]
mod tests;

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
    /// §3.5's (`--board`, `--principal`) pair: arm 2, the last binding for
    /// it; arm 3, no binding and the lone device key. `None` for the
    /// principal where the board has exactly one binding in the store.
    Board { origin: &'a Origin, principal: Option<u64> },
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
/// origin carries `://`. Its `Display` is the line without its newline, and
/// [`FromStr`] reads one back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Enrollment { origin: Origin, principal: u64, account: String, fingerprint: Fingerprint },
    Signed { dialed: Origin, signed: Origin },
}

/// The line, without its newline.
impl fmt::Display for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Binding::Enrollment { origin, principal, account, fingerprint } => write!(f, "{origin} {principal} {account} {fingerprint}"),
            Binding::Signed { dialed, signed } => write!(f, "signed {dialed} {signed}"),
        }
    }
}

/// A line of neither form — a hand-edited stray, which the bindings file's
/// reader ignores as it ignores a torn final line (§3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NotABinding;

impl fmt::Display for NotABinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a bindings-file line: neither `origin principal account fingerprint` nor `signed <dialed-origin> <signed-origin>`")
    }
}

impl std::error::Error for NotABinding {}

/// One line read back, in either of its two forms.
impl FromStr for Binding {
    type Err = NotABinding;

    fn from_str(line: &str) -> Result<Binding, NotABinding> {
        let origin = |text: &str| Origin::parse(text).ok_or(NotABinding);
        match line.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["signed", dialed, signed] => Ok(Binding::Signed { dialed: origin(dialed)?, signed: origin(signed)? }),
            [first, principal, account, fingerprint] if first.contains("://") => Ok(Binding::Enrollment {
                origin: origin(first)?,
                principal: principal.parse().map_err(|_| NotABinding)?,
                account: account.to_string(),
                fingerprint: Fingerprint::parse_hex(fingerprint).ok_or(NotABinding)?,
            }),
            _ => Err(NotABinding),
        }
    }
}

/// The public facts of one key in the store — what a lookup answers, what
/// `fingerprint --dir` lists and what a lookup's halt names. No seed: a key
/// signs through [`KeyStore::signer`]. The key's `ALGS` token is
/// `public.alg()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFacts {
    pub path: PathBuf,
    pub fingerprint: Fingerprint,
    pub public: PublicKey,
    pub label: Option<String>,
    pub anchor: bool,
}

impl KeyFacts {
    /// A loaded file's public facts, at `path`.
    fn of(path: PathBuf, file: &KeyFile) -> KeyFacts {
        KeyFacts { path, fingerprint: file.fingerprint, public: file.public.clone(), label: file.label.clone(), anchor: file.anchor }
    }
}

/// What the store could not do. Non-exhaustive: a later custody rung's
/// refusals join it (§1.4).
#[derive(Debug)]
#[non_exhaustive]
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
        }
    }
}

impl std::error::Error for StoreError {}

/// THE ONE WAY [`KeyStore::bind`] FAILS: the bindings file could not be
/// appended — a read-only mount, a missing permission — and the line rides
/// the failure for the person to record by hand. A WARNING and never a
/// refusal (§3.7): its `Display` is the warning a walk prints, and no walk
/// halts on it.
#[derive(Debug)]
pub struct Unappended {
    pub path: PathBuf,
    pub line: String,
    pub error: io::Error,
}

impl fmt::Display for Unappended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the bindings file {} could not be appended ({}); record this binding line yourself: {}",
            self.path.display(),
            self.error,
            self.line
        )
    }
}

impl std::error::Error for Unappended {}

/// A store refusal as AUTH-5.67's halt naming the path and the state — the
/// conversion a walk's `?` makes.
impl From<StoreError> for Halt {
    fn from(e: StoreError) -> Halt {
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
}

/// §3.5 arm 4's three forks on `claimant`, the keyless residue keyed on the
/// claimed board's mode (AUTH-5.86).
pub fn arm4_face(store: &FileStore, keys: &[KeyFacts], mode: Mode) -> Halt {
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
            let residue = if mode == Mode::ClaimedPermissive {
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
    /// The signer `sel` names, an anchor refused (§2.2's selection test) —
    /// THE ONE WAY a stored key signs: every walk takes a stored key's signer
    /// here, and its public facts from the lookup.
    fn signer(&self, sel: &KeySelector<'_>) -> Result<Box<dyn Signer>, StoreError>;
    /// Every binding line for `origin`, in file order (the newest last).
    fn bindings(&self, origin: &Origin) -> Result<Vec<Binding>, StoreError>;
    /// Append one line under the lock; the one failure is [`Unappended`],
    /// a warning carrying the line.
    fn bind(&self, b: &Binding) -> Result<(), Unappended>;
}

/// The default store on every platform: `~/.skep/` (§6; §9 item 10, RULED —
/// the ssh convention; the user profile's `.skep` on Windows).
pub fn default_store_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| PathBuf::from(home).join(".skep"))
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
    /// Both are read as the filesystem will resolve them (`resolved`): a
    /// destination the backup moment is about to create may lie several
    /// directories deep, or reach the store through a relative path or a
    /// symlink, and the store itself may not be made yet.
    pub fn contains_path(&self, path: &Path) -> bool {
        resolved(path).starts_with(resolved(&self.root))
    }

    /// The directory `0700`, created once (§3.3); the umask irrelevant. A
    /// failure names the directory it could not make.
    fn ensure_dirs(&self) -> Result<(), (PathBuf, io::Error)> {
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
            builder.create(&dir).map_err(|error| (dir.clone(), error))?;
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
    /// the path) — the seed with it. The store's own reader, and a suite's
    /// for a key another party holds; a walk reads [`FileStore::select`]'s
    /// facts and signs through [`KeyStore::signer`].
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

    /// This store's DEVICE keys — every key file whose `anchor` member is
    /// false, in [`FileStore::list`]'s order; an anchor copied in is never
    /// "this store's own" (§3.4; AUTH-5.28).
    pub fn device_keys(&self) -> Result<Vec<KeyFacts>, StoreError> {
        Ok(self.list()?.into_iter().filter(|k| !k.anchor).collect())
    }

    fn facts_of(&self, path: &Path) -> Result<KeyFacts, StoreError> {
        let file = self.load(path)?;
        Ok(KeyFacts::of(path.to_path_buf(), &file))
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
        Ok(complete.lines().filter_map(|line| line.parse().ok()).collect())
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

    /// The `new_id` a persist-first line recorded for `account` at `origin`
    /// — the principal of the LAST enrollment line naming that account —
    /// where one stands (§4.3; AUTH-5.20): the `new_id` an interrupted
    /// `delegate` was sent under, or was about to be.
    pub fn persisted_new_id(&self, origin: &Origin, account: &str) -> Result<Option<u64>, StoreError> {
        Ok(self.all_bindings()?.into_iter().rev().find_map(|b| match b {
            Binding::Enrollment { origin: o, principal, account: a, .. } if &o == origin && a == account => Some(principal),
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
    /// an anchor file is refused at every arm (§2.2's selection test). The
    /// answer is the selected key's PUBLIC facts; its signer is
    /// [`KeyStore::signer`]'s, over the same lookup.
    pub fn select(&self, sel: &KeySelector<'_>, purpose: Purpose) -> Result<KeyFacts, StoreError> {
        let (path, file) = self.selected(sel, purpose)?;
        Ok(KeyFacts::of(path, &file))
    }

    /// The lookup's one body: the selected key's path and its file, the seed
    /// with it — private, so the seed leaves the store only as a signer.
    fn selected(&self, sel: &KeySelector<'_>, purpose: Purpose) -> Result<(PathBuf, KeyFile), StoreError> {
        let judged = |path: PathBuf| -> Result<(PathBuf, KeyFile), StoreError> {
            let file = self.load(&path)?;
            if purpose == Purpose::Sign && file.anchor {
                return Err(StoreError::KeyFile { path, error: KeyFileError::AnchorAtSigningCommand });
            }
            Ok((path, file))
        };
        match sel {
            KeySelector::Path(path) => judged(path.to_path_buf()),
            KeySelector::Board { origin, principal } => {
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
                judged(Self::one_of(&matches, prefix)?)
            }
            KeySelector::Label(label) => {
                let keys = self.list()?;
                let matches: Vec<&KeyFacts> = keys.iter().filter(|k| k.label.as_deref() == Some(*label)).collect();
                judged(Self::one_of(&matches, label)?)
            }
        }
    }

    /// The one match's path; none, or more than one listed and never a pick.
    fn one_of(matches: &[&KeyFacts], select: &str) -> Result<PathBuf, StoreError> {
        match matches {
            [] => Err(StoreError::NotFound { select: select.to_string() }),
            [one] => Ok(one.path.clone()),
            many => Err(StoreError::Ambiguous { keys: many.iter().map(|k| (*k).clone()).collect() }),
        }
    }

    /// Append `line` to the bindings file in ONE `write` under the advisory
    /// lock on `<store>/lock` (§3.7). A failed append — a read-only mount —
    /// is [`Unappended`], carrying the line for the person to record.
    pub fn append_line(&self, line: &str) -> Result<(), Unappended> {
        let path = self.bindings_path();
        let text = format!("{line}\n");
        let read_only = |error: io::Error| Unappended { path: path.clone(), line: line.to_string(), error };
        self.ensure_dirs().map_err(|(_, error)| read_only(error))?;
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

/// `path` as the filesystem will resolve it once its missing directories
/// are made: absolute against the working directory, its deepest EXISTING
/// ancestor canonicalized — every symlink and `..` in it resolved — and the
/// components below that ancestor re-joined lexically, which is exact
/// because none of them exists yet, so no link lies among them.
fn resolved(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let components: Vec<Component<'_>> = absolute.components().collect();
    for split in (1..=components.len()).rev() {
        let head: PathBuf = components[..split].iter().collect();
        let Ok(mut out) = fs::canonicalize(&head) else { continue };
        for component in &components[split..] {
            match component {
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(name) => out.push(name),
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
        return out;
    }
    absolute
}

impl KeyStore for FileStore {
    fn generate(&self, label: Option<Label>) -> Result<KeyId, StoreError> {
        self.ensure_dirs().map_err(|(path, error)| StoreError::Io { path, error })?;
        let file = KeyFile::new(Seed::fresh(), false, label, None);
        let path = self.key_path(&file.fingerprint);
        Self::write_once(&path, file.to_json().as_bytes()).map_err(|error| StoreError::Io { path, error })?;
        Ok(KeyId(file.fingerprint))
    }

    fn signer(&self, sel: &KeySelector<'_>) -> Result<Box<dyn Signer>, StoreError> {
        let (_, file) = self.selected(sel, Purpose::Sign)?;
        Ok(Box::new(file.signer()))
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

    fn bind(&self, b: &Binding) -> Result<(), Unappended> {
        self.append_line(&b.to_string())
    }
}
