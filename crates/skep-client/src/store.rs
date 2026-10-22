//! The key store (`client.md` §3).
//!
//! It is the `KeyStore` seam (§1.4) — `generate`, `signer`, `bindings`,
//! `bind` — and its `FileStore` arm, plain files with modes (§3a's rung 1):
//! `<store>/keys/<fingerprint>.key` in a `0700` directory, written once —
//! its bytes under `O_EXCL` at mode `0600` to `<fingerprint>.key.tmp`,
//! synced, then published by a rename and the directory's sync, so no
//! lookup reads a key file cut short (§3.3, §3.7) — the append-only
//! `bindings` file in its two line forms (§3.5) under the advisory lock
//! `<store>/lock` (§3.7), and no anchor under the store, ever (§3.4;
//! AUTH-5.54 step 3). The store is the seed's custodian (§3a: "signing and
//! key lookup behind `Signer` and `KeyStore`"): a lookup answers a key's
//! public facts, [`KeyFacts`], and the seed leaves a lookup only as the
//! signer [`KeyStore::signer`] derives from it — [`FileStore::load`], the
//! store's own reader, hands a file out with its seed — so a later custody
//! rung is a different signer behind that one method, never a rewrite of a
//! walk (§1.4). The refusals are the store's own faces ([`StoreError`],
//! [`KeyFileError`]), never wire tokens, each converted into AUTH-5.67's
//! halt naming the state, and the path where there is one, by
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
use crate::sheet::{read_key_file, render_inert, KeyFile, KeyFileError, Label, Seed};
use crate::sign::Signer;

#[cfg(test)]
mod tests;

/// A key's identity in the store — its fingerprint, the file's name (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub Fingerprint);

/// §3.5's lookup input (§1.4).
///
/// It is a key-file path, the (`--board`, `--principal`) pair the binding
/// and lone-key arms take, or `fingerprint --select`'s prefix-or-label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySelector<'a> {
    /// `--key <path>` / `SKEP_KEY`: that file, no lookup (arm 1).
    Path(&'a Path),
    /// §3.5's (`--board`, `--principal`) pair.
    ///
    /// Arm 2 is the last binding for it; arm 3, no binding selected and the
    /// lone device key. `None` stands for the principal where the board has
    /// exactly one binding in the store.
    Board { origin: &'a Origin, principal: Option<u64> },
    /// A fingerprint prefix, 2–64 characters of `[0-9a-f]`.
    Prefix(&'a str),
    /// A label — not unique by rule (AUTH-5.3).
    Label(&'a str),
}

impl<'a> KeySelector<'a> {
    /// Returns `fingerprint --select`'s arm for `text`, told apart by shape.
    ///
    /// 2–64 characters all in `[0-9a-f]` is a prefix, anything else a label.
    pub fn select(text: &'a str) -> KeySelector<'a> {
        let hexy = (2..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if hexy { KeySelector::Prefix(text) } else { KeySelector::Label(text) }
    }
}

/// What a selected key is to be used for.
///
/// It is signing (or enrollment as a device key), where an anchor file is
/// refused whichever arm selected it (§2.2's selection test, P11); or a
/// read of its public facts (`fingerprint --key`, `verify`), where it is
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// To sign, or to be enrolled as a device key.
    Sign,
    /// To read the key's public facts.
    Read,
}

/// One line of the bindings file, in either of its two forms (§3.5).
///
/// The two are the enrollment line `origin principal account fingerprint`
/// (AUTH-5.76's retention) and the `signed <dialed-origin> <signed-origin>`
/// line a frontend at its own bind-override node writes (AUTH-4.57 (a)'s
/// client half), and there is no third. They are told apart by the first
/// field — a canonical origin carries `://`. Its `Display` is the line
/// without its newline, and [`FromStr`] reads one back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// The enrollment line, `origin principal account fingerprint`.
    Enrollment { origin: Origin, principal: u64, account: String, fingerprint: Fingerprint },
    /// The `signed <dialed-origin> <signed-origin>` line.
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

/// A line of neither form — a hand-edited stray.
///
/// The bindings file's reader ignores it as it ignores a torn final line
/// (§3.7).
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

/// The public facts of one key in the store.
///
/// They are what a lookup answers, what `fingerprint --dir` lists and what
/// a lookup's halt names. No seed: a key signs through [`KeyStore::signer`].
/// The key's `ALGS` token is `public.alg()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFacts {
    /// The key file's path.
    pub path: PathBuf,
    /// The key's fingerprint.
    pub fingerprint: Fingerprint,
    /// The public key.
    pub public: PublicKey,
    /// The label, where the file carries one.
    pub label: Option<String>,
    /// Whether the file is an anchor's.
    pub anchor: bool,
}

impl KeyFacts {
    /// Returns a loaded file's public facts, at `path`.
    fn of(path: PathBuf, file: &KeyFile) -> KeyFacts {
        KeyFacts { path, fingerprint: file.fingerprint, public: file.public.clone(), label: file.label.clone(), anchor: file.anchor }
    }
}

/// What the store could not do.
///
/// Non-exhaustive: a later custody rung's refusals join it (§1.4).
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// A key file refused by its own contents, read alone.
    ///
    /// The file is the one a caller named or a lookup selected; one refused
    /// while the store was listed is [`StoreError::Unlistable`]. AUTH-5.67's
    /// halt names the path and the state.
    KeyFile { path: PathBuf, error: KeyFileError },
    /// A `keys/` file a listing of the store could not read as a key.
    ///
    /// Its own contents refuse it (§3.2). Every lookup that lists the store
    /// reads each `*.key` file under `keys/` — §3.5 arm 3, `--select`, the
    /// device keys — so one such file stops them all, and AUTH-5.67's halt
    /// names the file and the act that clears it.
    Unlistable { path: PathBuf, error: KeyFileError },
    /// A path missing, unreadable or mis-pathed.
    ///
    /// It is halt and surface naming it, never a fallback (AUTH-5.67).
    Io { path: PathBuf, error: io::Error },
    /// A key the store could not write.
    ///
    /// Its directory or its file could not be made, written or synced. A key
    /// file enters the store whole or not at all (§3.3, §3.7), so no lookup
    /// meets a part of this key.
    Unwritten { path: PathBuf, error: io::Error },
    /// A binding's fingerprint names no file in the store.
    MissingKey { path: PathBuf, fingerprint: Fingerprint },
    /// §3.5 arm 4: no key was selected.
    ///
    /// The store's keys are listed for the caller to fork the face on
    /// `claimant`.
    NoSelection { keys: Vec<KeyFacts> },
    /// More than one key matches a `--select`.
    ///
    /// Every match is listed, never a pick (`client.md` §2.2).
    Ambiguous { keys: Vec<KeyFacts> },
    /// No key matches a `--select`.
    NotFound { select: String },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::KeyFile { path, error } | StoreError::Unlistable { path, error } => write!(f, "{}: {error}", path.display()),
            StoreError::Io { path, error } | StoreError::Unwritten { path, error } => write!(f, "{}: {error}", path.display()),
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

/// The one way [`KeyStore::bind`] fails.
///
/// The bindings file could not be appended — a read-only mount, a missing
/// permission — and the line rides the failure for the person to record by
/// hand. It is a warning and never a refusal (§3.7): its `Display` is the
/// warning a walk prints, and no walk halts on it.
#[derive(Debug)]
pub struct Unappended {
    /// The bindings file's path.
    pub path: PathBuf,
    /// The line that was not appended.
    pub line: String,
    /// The I/O error the append met.
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

/// A store refusal as AUTH-5.67's halt naming the state and its path.
///
/// A refusal with no path — [`StoreError::NoSelection`],
/// [`StoreError::Ambiguous`], [`StoreError::NotFound`] — names the state
/// alone. It is the conversion a walk's `?` makes.
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
            StoreError::Unlistable { path, error } => {
                let keys = path.parent().unwrap_or(path.as_path()).display().to_string();
                Halt::face(
                    format!("the key store holds a file it cannot read as a key: {}: {error}", path.display()),
                    "every lookup that lists the store reads each `*.key` file under `keys/` — the lone device key's, `--select`, a walk's own \
                     keys — and this file's own contents refuse it (client.md §3.2); a copy or a write that stopped part-way leaves such a \
                     file, as does a hand edit",
                    match error {
                        KeyFileError::Newer { .. } => "upgrade skep: a newer skep wrote this key, and every listing of this store reads it".to_string(),
                        _ => format!(
                            "move {} out of {keys} — aside, not deleted, since it may be a key you hold nowhere else; once it is gone the store \
                             lists again",
                            path.display()
                        ),
                    },
                )
            }
            StoreError::Io { path, error } => Halt::face(
                format!("the key file {} is missing, unreadable or mis-pathed: {error}", path.display()),
                "AUTH-5.67: a key file missing, unreadable or mis-pathed is HALT AND SURFACE, never a fallback to a bare bind",
                "check the path (`--key`, `SKEP_KEY`, `--dir`)",
            ),
            StoreError::Unwritten { path, error } => {
                let volume = path.parent().unwrap_or(path.as_path()).display().to_string();
                Halt::face(
                    format!("the key store could not write {}: {error}", path.display()),
                    "a generation the store cannot finish — at a full volume or quota, a file-size limit, a read-only or failing volume — \
                     makes no key: a key file enters `keys/` only whole, and what the run wrote toward one is removed",
                    format!("free room on the volume holding {volume}, or make it writable; then run this again"),
                )
            }
            StoreError::MissingKey { path, fingerprint } => Halt::face(
                format!("the bindings name key {fingerprint} and the store holds no file at {}", path.display()),
                "the key file was removed from the store after the binding was written",
                "restore the file, or re-run the hop that binds another key",
            ),
            other => Halt::face("the key store refused", other.to_string(), "see the store's state above"),
        }
    }
}

/// Returns §3.5 arm 4's face, in its three forks on `mode` and `keys`.
///
/// The keyless residue is keyed on the claimed board's mode (AUTH-5.86).
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

/// The key store's seam (§1.4).
///
/// Rung 2's `generate` mints the keychain item the file then indexes, which
/// no `Signer` can do — the trait's one non-signing key job and its warrant
/// (§9 item 26). `generate` takes no anchor flag: an anchor is generated by
/// the ceremony's own in-memory signer and exported, never through the
/// store (§3.4).
pub trait KeyStore {
    /// Generates one device key of the production kind from a fresh OS seed.
    ///
    /// Its file is written once and enters the store whole or not at all
    /// (§3.3, §3.7); the fingerprint names it.
    ///
    /// # Errors
    ///
    /// The file store's [`StoreError::Unwritten`], naming the directory it
    /// could not make or the key it could not write; the store removes what
    /// the call wrote toward the key.
    fn generate(&self, label: Option<Label>) -> Result<KeyId, StoreError>;
    /// Returns the signer `sel` names, an anchor refused.
    ///
    /// The refusal is §2.2's selection test. This is the one way a stored
    /// key signs: every walk takes a stored key's signer here, and its public
    /// facts from the lookup.
    ///
    /// # Errors
    ///
    /// The lookup's refusals — the file store's are [`FileStore::select`]'s
    /// under [`Purpose::Sign`] — an anchor file among them, as
    /// [`KeyFileError::AnchorAtSigningCommand`].
    fn signer(&self, sel: &KeySelector<'_>) -> Result<Box<dyn Signer>, StoreError>;
    /// Returns every binding line for `origin`, in file order.
    ///
    /// The newest is last.
    ///
    /// # Errors
    ///
    /// The file store's [`StoreError::Io`] where the bindings file stands and
    /// cannot be read.
    fn bindings(&self, origin: &Origin) -> Result<Vec<Binding>, StoreError>;
    /// Appends one line under the lock.
    ///
    /// # Errors
    ///
    /// The one failure is [`Unappended`], a warning carrying the line.
    fn bind(&self, b: &Binding) -> Result<(), Unappended>;
}

/// Returns the default store on every platform: `~/.skep/` (§6; §9 item 10).
///
/// It follows the ssh convention; on Windows it is the user profile's
/// `.skep`.
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
    /// Opens the store at `root`; nothing is created until a write.
    pub fn open(root: impl Into<PathBuf>) -> FileStore {
        FileStore { root: root.into() }
    }

    /// Returns the store's directory.
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

    /// Returns the path a key of `fp` rests at.
    pub fn key_path(&self, fp: &Fingerprint) -> PathBuf {
        self.keys_dir().join(format!("{}.key", fp.to_hex()))
    }

    /// Returns whether `path` lies under this store (§3.4's check).
    ///
    /// Under the store an anchor file is refused (the backup moment's
    /// destination; a later `--anchor`). Both are read as the filesystem will
    /// resolve them (`resolved`): a destination the backup moment is about to
    /// create may lie several directories deep, or reach the store through a
    /// relative path or a symlink, and the store itself may not be made yet.
    pub fn contains_path(&self, path: &Path) -> bool {
        resolved(path).starts_with(resolved(&self.root))
    }

    /// Creates the store's directories at mode `0700`, once (§3.3).
    ///
    /// The umask is irrelevant.
    ///
    /// # Errors
    ///
    /// A failure names the directory it could not make.
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

    /// Writes `bytes` to a new file at `path`, once (§3.3).
    ///
    /// The open is `O_CREAT|O_EXCL` with mode `0600` set at creation — never
    /// chmod'd after a world-readable moment. It is the one writer every key
    /// file and anchor file of this crate goes through. A write or a sync
    /// that fails removes the file the call created, best effort; a kill
    /// leaves what was written, so the store writes its key files beside
    /// their names and renames them into place (`publish`).
    ///
    /// # Errors
    ///
    /// The open's, the write's and the sync's I/O errors — `AlreadyExists`
    /// where a file stands at `path`, which the call leaves as it stands.
    pub fn write_once(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(e);
        }
        Ok(())
    }

    /// Puts `bytes` at `path` whole or not at all (§3.3, §3.7).
    ///
    /// The bytes go to `<path>.tmp` — for a key file `<fingerprint>.key.tmp`,
    /// a name [`FileStore::list`] never reads — under
    /// [`FileStore::write_once`]; a rename then makes `path`, and the
    /// directory is synced so the name is as durable as the bytes. A failure
    /// removes what the call made, best effort; only a kill leaves a `.tmp`
    /// behind.
    ///
    /// **Precondition.** No file stands at `path`, which a rename replaces:
    /// the one caller names a fresh key by its fingerprint.
    ///
    /// # Errors
    ///
    /// The write's, the rename's and the directory sync's I/O errors.
    fn publish(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        Self::write_once(&tmp, bytes)?;
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = sync_parent(path) {
            let _ = fs::remove_file(path);
            return Err(e);
        }
        Ok(())
    }

    /// Loads and judges one key file, the seed with it (§3.2's reader).
    ///
    /// It is the store's own reader, and a suite's for a key another party
    /// holds; a walk reads [`FileStore::select`]'s facts and signs through
    /// [`KeyStore::signer`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] where the file cannot be read or is no regular
    /// file, and [`StoreError::KeyFile`] where its own contents refuse it —
    /// AUTH-5.67's halt names the path.
    pub fn load(&self, path: &Path) -> Result<KeyFile, StoreError> {
        let bytes = read_key_file(path).map_err(|error| StoreError::Io { path: path.to_path_buf(), error })?;
        KeyFile::parse(&bytes).map_err(|error| StoreError::KeyFile { path: path.to_path_buf(), error })
    }

    /// Returns the public facts of every key file in the store.
    ///
    /// They come in file name order. Only the `*.key` files under `keys/` are
    /// read: a key not yet published, `*.key.tmp`, is never listed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] where the keys directory stands and cannot be read,
    /// or a key file under it cannot be read; [`StoreError::Unlistable`]
    /// where a key file's own contents refuse it — one such file stops the
    /// whole listing, and its face names the file and the act that clears it.
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
        paths
            .iter()
            .map(|p| {
                self.facts_of(p).map_err(|e| match e {
                    StoreError::KeyFile { path, error } => StoreError::Unlistable { path, error },
                    other => other,
                })
            })
            .collect()
    }

    /// Returns this store's device keys.
    ///
    /// They are every key file whose `anchor` member is false, in
    /// [`FileStore::list`]'s order; an anchor copied in is never "this store's
    /// own" (§3.4; AUTH-5.28).
    ///
    /// # Errors
    ///
    /// [`FileStore::list`]'s errors.
    pub fn device_keys(&self) -> Result<Vec<KeyFacts>, StoreError> {
        Ok(self.list()?.into_iter().filter(|k| !k.anchor).collect())
    }

    fn facts_of(&self, path: &Path) -> Result<KeyFacts, StoreError> {
        let file = self.load(path)?;
        Ok(KeyFacts::of(path.to_path_buf(), &file))
    }

    /// Returns every binding line, in file order.
    ///
    /// A final line without `\n` is ignored (§3.7: a torn append is never a
    /// torn record).
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] where the bindings file stands and cannot be read.
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

    /// Returns the last enrollment line for (`origin`, `principal`).
    ///
    /// The newest wins (§3.5 arm 2).
    ///
    /// # Errors
    ///
    /// [`FileStore::all_bindings`]'s errors.
    pub fn enrollment_for(&self, origin: &Origin, principal: u64) -> Result<Option<(String, Fingerprint)>, StoreError> {
        Ok(self.all_bindings()?.into_iter().rev().find_map(|b| match b {
            Binding::Enrollment { origin: o, principal: p, account, fingerprint } if &o == origin && p == principal => {
                Some((account, fingerprint))
            }
            _ => None,
        }))
    }

    /// Returns the `new_id` a persist-first line recorded for `account`.
    ///
    /// It is the principal of the last enrollment line naming that account
    /// at `origin`, where one stands (§4.3; AUTH-5.20): the `new_id` an
    /// interrupted `delegate` was sent under, or was about to be.
    ///
    /// # Errors
    ///
    /// [`FileStore::all_bindings`]'s errors.
    pub fn persisted_new_id(&self, origin: &Origin, account: &str) -> Result<Option<u64>, StoreError> {
        Ok(self.all_bindings()?.into_iter().rev().find_map(|b| match b {
            Binding::Enrollment { origin: o, principal, account: a, .. } if &o == origin && a == account => Some(principal),
            _ => None,
        }))
    }

    /// Returns the principals bound at `origin`, newest first, each once.
    ///
    /// This is the one-binding test that lets `--principal` be omitted
    /// (`client.md` §3.5: "`--principal` may be omitted where the board has
    /// exactly one binding in the store, the agent space's line not counting:
    /// §4.3's persist-first line binds the account's first child
    /// (`inc(account, 1)`), so a claimed board always holds that line beside
    /// the account's, and the one-binding test excludes every line whose
    /// account is the first child of another line's account at the same
    /// board"). The exclusion is one condition: a line is dropped where its
    /// account is [`first_child`] of another line's account at this origin.
    ///
    /// # Errors
    ///
    /// [`FileStore::all_bindings`]'s errors.
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

    /// Returns the `signed` line's origin for `dialed` (§3.5).
    ///
    /// The answer is `None` where no such line stands.
    ///
    /// # Errors
    ///
    /// [`FileStore::all_bindings`]'s errors.
    pub fn signed_origin_for(&self, dialed: &Origin) -> Result<Option<Origin>, StoreError> {
        Ok(self.all_bindings()?.into_iter().rev().find_map(|b| match b {
            Binding::Signed { dialed: d, signed } if &d == dialed => Some(signed),
            _ => None,
        }))
    }

    /// Looks up the key `sel` selects (§3.5), answering its public facts.
    ///
    /// Its signer is [`KeyStore::signer`]'s, over the same lookup.
    ///
    /// # Errors
    ///
    /// The lookup runs in its precedence: (1) a path; (2) the last binding
    /// for (origin, principal); (3) no binding selected and exactly one
    /// device key in the store; (4) otherwise [`StoreError::NoSelection`]
    /// with the keys listed, for the caller's fork on `claimant`. Under
    /// [`Purpose::Sign`] an anchor file is refused at every arm (§2.2's
    /// selection test). A binding whose key file is gone is
    /// [`StoreError::MissingKey`]; a prefix or a label that matches no key is
    /// [`StoreError::NotFound`], and one that matches more than one
    /// [`StoreError::Ambiguous`]; a key file is refused as [`FileStore::load`]
    /// refuses it, and an arm that lists the store — arm 3, a prefix, a
    /// label — meets [`FileStore::list`]'s refusals.
    pub fn select(&self, sel: &KeySelector<'_>, purpose: Purpose) -> Result<KeyFacts, StoreError> {
        let (path, file) = self.selected(sel, purpose)?;
        Ok(KeyFacts::of(path, &file))
    }

    /// Returns the selected key's path and its file, the seed with it.
    ///
    /// It is the lookup's one body — private, so the seed leaves the lookup
    /// only as a signer.
    ///
    /// # Errors
    ///
    /// [`FileStore::select`]'s errors.
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

    /// Returns the one match's path.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] for none, and [`StoreError::Ambiguous`] for
    /// more than one, listed and never a pick.
    fn one_of(matches: &[&KeyFacts], select: &str) -> Result<PathBuf, StoreError> {
        match matches {
            [] => Err(StoreError::NotFound { select: select.to_string() }),
            [one] => Ok(one.path.clone()),
            many => Err(StoreError::Ambiguous { keys: many.iter().map(|k| (*k).clone()).collect() }),
        }
    }

    /// Appends `line` to the bindings file in one `write` (§3.7).
    ///
    /// The write runs under the advisory lock on `<store>/lock`.
    ///
    /// # Errors
    ///
    /// A failed append — a read-only mount — is [`Unappended`], carrying the
    /// line for the person to record.
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

/// Syncs the directory holding `path`, so a rename into it is durable.
///
/// A directory that takes no sync is no failure: a filesystem that answers
/// the sync `Unsupported`, or `InvalidInput` as some answer a directory's —
/// there the name is as durable as the filesystem makes it.
///
/// # Errors
///
/// An I/O error opening or syncing the directory, save those two.
#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    match fs::File::open(dir)?.sync_all() {
        Err(e) if matches!(e.kind(), io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput) => Ok(()),
        other => other,
    }
}

/// Syncs nothing: on this platform a directory opens as no file.
///
/// A rename here is as durable as the filesystem makes it.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Returns `path` as the filesystem will resolve it.
///
/// The resolution is the one that holds once its missing directories are
/// made: absolute against the working directory, its deepest existing
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
        self.ensure_dirs().map_err(|(path, error)| StoreError::Unwritten { path, error })?;
        let file = KeyFile::new(Seed::fresh(), false, label, None);
        let path = self.key_path(&file.fingerprint);
        Self::publish(&path, file.to_json().as_bytes()).map_err(|error| StoreError::Unwritten { path, error })?;
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
