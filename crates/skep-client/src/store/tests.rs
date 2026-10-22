//! The store (`client.md` §3): the modes, `O_EXCL`, a key file entering the
//! store whole or not at all, the doctored files' refusals — read alone and
//! met by a listing — the lookup's arms, the two line forms, each append a
//! line of its own, the lock.

use std::fs;

use super::*;

fn store() -> (tempfile::TempDir, FileStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open(dir.path().join("store"));
    (dir, store)
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// §3.3 — the directory `0700`, the file `0600`; §3.7 — a second `keygen`
/// makes a second file under `O_EXCL` and never rewrites the first, each
/// published whole under its name with no `.tmp` left beside it.
#[test]
fn generate_writes_once_under_the_modes() {
    let (_dir, store) = store();
    let a = store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let b = store.generate(None).unwrap();
    assert_ne!(a, b);
    let keys = store.list().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| !k.anchor));
    let mut names: Vec<String> = fs::read_dir(store.root().join("keys")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    let mut expected = vec![format!("{}.key", a.0.to_hex()), format!("{}.key", b.0.to_hex())];
    names.sort();
    expected.sort();
    assert_eq!(names, expected, "every key file under its own name, and nothing beside them");
    #[cfg(unix)]
    {
        assert_eq!(mode(store.root()), 0o700);
        assert_eq!(mode(&store.key_path(&a.0)), 0o600);
    }
    let path = store.key_path(&a.0);
    assert!(FileStore::write_once(&path, b"x").is_err(), "a second write at the same name is refused");
    let file = store.load(&path).unwrap();
    assert_eq!(file.label.as_deref(), Some("notebook"));
    assert_eq!(file.fingerprint, a.0);
}

/// §3.4 — the store's DEVICE keys are its key files whose `anchor` member is
/// false: an anchor file copied into `keys/` is listed by `list` and is never
/// one of `device_keys`.
#[test]
fn the_device_keys_leave_an_anchor_copied_in_out() {
    let (_dir, store) = store();
    let a = store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let b = store.generate(Some(Label::new("phone").unwrap())).unwrap();
    let anchor = KeyFile::new(Seed::new([7u8; 32]), true, Some(Label::new("paper-a").unwrap()), None);
    FileStore::write_once(&store.key_path(&anchor.fingerprint), anchor.to_json().as_bytes()).unwrap();
    assert_eq!(store.list().unwrap().len(), 3, "the copied anchor is a key file of the store");
    let mut devices: Vec<Fingerprint> = store.device_keys().unwrap().iter().map(|k| k.fingerprint).collect();
    let mut expected = vec![a.0, b.0];
    devices.sort_by_key(Fingerprint::to_hex);
    expected.sort_by_key(Fingerprint::to_hex);
    assert_eq!(devices, expected, "the anchor is never this store's own device key");
}

/// §3.2's refusals from doctored files, each a state beside the path: a `v`
/// of 2, an unknown member, a seed the fingerprint does not re-derive from,
/// and an anchor file at a signing selection.
#[test]
fn doctored_files_are_refused_by_state() {
    let (dir, store) = store();
    let id = store.generate(None).unwrap();
    let path = store.key_path(&id.0);
    let text = fs::read_to_string(&path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let write = |name: &str, v: &serde_json::Value| -> PathBuf {
        let p = dir.path().join(name);
        fs::write(&p, v.to_string()).unwrap();
        p
    };
    v["v"] = serde_json::Value::from(2);
    let newer = write("newer.key", &v);
    assert!(matches!(store.load(&newer), Err(StoreError::KeyFile { error: KeyFileError::Newer { v: 2 }, .. })));
    v["v"] = serde_json::Value::from(1);
    v["custody"] = serde_json::Value::from("keychain");
    let unknown = write("unknown.key", &v);
    assert!(matches!(store.load(&unknown), Err(StoreError::KeyFile { error: KeyFileError::Schema { member }, .. }) if member == "custody"));
    v.as_object_mut().unwrap().remove("custody");
    v["seed"] = serde_json::Value::from("11".repeat(32));
    let disagrees = write("disagrees.key", &v);
    assert!(matches!(store.load(&disagrees), Err(StoreError::KeyFile { error: KeyFileError::Disagrees, .. })));
    // An anchor file at `--key` for a signing command.
    let anchor = KeyFile::new(Seed::new([5u8; 32]), true, Some(Label::new("paper-a").unwrap()), None);
    let anchor_path = dir.path().join("anchor.skep-key");
    FileStore::write_once(&anchor_path, anchor.to_json().as_bytes()).unwrap();
    assert!(matches!(
        store.select(&KeySelector::Path(&anchor_path), Purpose::Sign),
        Err(StoreError::KeyFile { error: KeyFileError::AnchorAtSigningCommand, .. })
    ));
    assert!(store.select(&KeySelector::Path(&anchor_path), Purpose::Read).is_ok(), "a read of its public facts is admitted");
    assert!(matches!(store.load(&dir.path().join("missing.key")), Err(StoreError::Io { .. })));
}

/// §3.5 — the lookup's four arms: a path; the LAST binding for the pair;
/// the lone device key; otherwise no selection with the keys listed.
#[test]
fn the_lookup_takes_its_four_arms_in_order() {
    let (_dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    // Arm 4, the store EMPTY.
    assert!(matches!(
        store.select(&KeySelector::Board { origin: &origin, principal: Some(1) }, Purpose::Sign),
        Err(StoreError::NoSelection { keys }) if keys.is_empty()
    ));
    // Arm 3: exactly one device key.
    let first = store.generate(Some(Label::new("one").unwrap())).unwrap();
    let sel = store.select(&KeySelector::Board { origin: &origin, principal: Some(1) }, Purpose::Sign).unwrap();
    assert_eq!(sel.fingerprint, first.0);
    // Two keys, no binding: arm 4 lists both.
    let second = store.generate(Some(Label::new("two").unwrap())).unwrap();
    assert!(matches!(
        store.select(&KeySelector::Board { origin: &origin, principal: Some(1) }, Purpose::Sign),
        Err(StoreError::NoSelection { keys }) if keys.len() == 2
    ));
    // Arm 2: the binding, and the LAST line wins.
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: first.0 }).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: second.0 }).unwrap();
    let sel = store.select(&KeySelector::Board { origin: &origin, principal: Some(1) }, Purpose::Sign).unwrap();
    assert_eq!(sel.fingerprint, second.0, "the newest line wins");
    // `--principal` omitted where the board has exactly one binding.
    let sel = store.select(&KeySelector::Board { origin: &origin, principal: None }, Purpose::Sign).unwrap();
    assert_eq!(sel.fingerprint, second.0);
    // Arm 1: a path, no lookup.
    let sel = store.select(&KeySelector::Path(&store.key_path(&first.0)), Purpose::Sign).unwrap();
    assert_eq!(sel.fingerprint, first.0);
    // `--select` by shape: a prefix, a label, an ambiguity listed and never
    // picked.
    let prefix = &first.0.to_hex()[..12];
    assert_eq!(store.select(&KeySelector::select(prefix), Purpose::Read).unwrap().fingerprint, first.0);
    assert_eq!(store.select(&KeySelector::select("two"), Purpose::Read).unwrap().fingerprint, second.0);
    assert!(matches!(store.select(&KeySelector::select("zz"), Purpose::Read), Err(StoreError::NotFound { .. })));
    store.generate(Some(Label::new("two").unwrap())).unwrap();
    assert!(matches!(store.select(&KeySelector::select("two"), Purpose::Read), Err(StoreError::Ambiguous { keys }) if keys.len() == 2));
}

/// §3a — the store is the seed's custodian: a lookup answers public facts,
/// and the key signs through `KeyStore::signer` over the same lookup — the
/// bound key's signer is that key's, an anchor's file is refused at it as at
/// every signing selection.
#[test]
fn a_stored_key_signs_through_the_store_and_an_anchor_never_does() {
    let (dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let id = store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    store.generate(None).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: id.0 }).unwrap();
    let bound = KeySelector::Board { origin: &origin, principal: Some(1) };
    let facts = store.select(&bound, Purpose::Sign).unwrap();
    assert_eq!((facts.fingerprint, facts.label.as_deref(), facts.path.clone()), (id.0, Some("notebook"), store.key_path(&id.0)));
    let signer = store.signer(&bound).unwrap();
    assert_eq!((signer.fingerprint(), signer.public_key()), (facts.fingerprint, &facts.public));
    let blob = signer.sign(b"bytes the library framed");
    assert!(skep_signature::verify(signer.tag(), &facts.public, b"bytes the library framed", &blob).is_ok());
    let anchor = KeyFile::new(Seed::new([6u8; 32]), true, Some(Label::new("paper-b").unwrap()), None);
    let anchor_path = dir.path().join("anchor.skep-key");
    FileStore::write_once(&anchor_path, anchor.to_json().as_bytes()).unwrap();
    assert!(matches!(store.signer(&KeySelector::Path(&anchor_path)), Err(StoreError::KeyFile { error: KeyFileError::AnchorAtSigningCommand, .. })));
}

/// §4.3 — the persist-first line read back: the LAST line naming the
/// account at the board answers its `new_id`; another account's or another
/// board's lines answer nothing.
#[test]
fn the_persisted_new_id_is_the_last_line_naming_the_account() {
    let (_dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    assert_eq!(store.persisted_new_id(&origin, "1.0.1.1").unwrap(), None);
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: fp }).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 424_242, account: "1.0.1.1".into(), fingerprint: fp }).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 525_252, account: "1.0.1.1".into(), fingerprint: fp }).unwrap();
    assert_eq!(store.persisted_new_id(&origin, "1.0.1.1").unwrap(), Some(525_252), "the newest line wins");
    assert_eq!(store.persisted_new_id(&origin, "1.0.1.2").unwrap(), None);
    assert_eq!(store.persisted_new_id(&Origin::parse("http://127.0.0.1:9").unwrap(), "1.0.1.1").unwrap(), None);
}

/// §3.5 — the two line forms and no third; §3.7 — a final line without
/// `\n` is ignored, the signed line is keyed by the origin DIALED.
#[test]
fn the_bindings_file_has_two_line_forms() {
    let (_dir, store) = store();
    let dialed = Origin::parse("http://127.0.0.1:8642").unwrap();
    let signed = Origin::parse("https://board.example").unwrap();
    let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    let enroll = Binding::Enrollment { origin: dialed.clone(), principal: 7, account: "1.0.1".into(), fingerprint: fp };
    assert_eq!(enroll.to_string(), format!("http://127.0.0.1:8642 7 1.0.1 {}", "ab".repeat(32)));
    assert_eq!(enroll.to_string().parse::<Binding>(), Ok(enroll.clone()));
    let sline = Binding::Signed { dialed: dialed.clone(), signed: signed.clone() };
    assert_eq!(sline.to_string(), "signed http://127.0.0.1:8642 https://board.example");
    assert_eq!(sline.to_string().parse::<Binding>(), Ok(sline.clone()));
    assert_eq!("retired abab".parse::<Binding>(), Err(NotABinding), "no third form");
    assert_eq!("http://127.0.0.1:8642 x 1.0.1 ab".parse::<Binding>(), Err(NotABinding), "a field outside its form");
    store.bind(&enroll).unwrap();
    store.bind(&sline).unwrap();
    assert_eq!(store.bindings(&dialed).unwrap().len(), 2);
    assert_eq!(store.signed_origin_for(&dialed).unwrap(), Some(signed));
    assert_eq!(store.enrollment_for(&dialed, 7).unwrap(), Some(("1.0.1".to_string(), fp)));
    // A torn final line is ignored.
    let path = store.root().join("bindings");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("http://127.0.0.1:8642 9 1.0.2 ");
    fs::write(&path, text).unwrap();
    assert_eq!(store.all_bindings().unwrap().len(), 2);
    #[cfg(unix)]
    {
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&store.root().join("lock")), 0o600);
    }
}

/// §3.7 — on a read-only store the append is a WARNING carrying the line,
/// never a refusal.
#[cfg(unix)]
#[test]
fn a_read_only_store_warns_with_the_line() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, store) = store();
    store.generate(None).unwrap();
    fs::set_permissions(store.root(), fs::Permissions::from_mode(0o500)).unwrap();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    let b = Binding::Enrollment { origin, principal: 1, account: "1.0.1".into(), fingerprint: fp };
    let warning = store.bind(&b).unwrap_err();
    fs::set_permissions(store.root(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(warning.line, b.to_string());
    assert!(warning.to_string().ends_with(&format!("record this binding line yourself: {b}")), "{warning}");
    assert!(warning.to_string().contains("a newline before it where the file does not end in one, and one after it"), "{warning}");
}

/// §3.7 — an append never changes how the bytes before it read.
///
/// Over every torn last line a bindings file can hold — each prefix of
/// either line form, the whole line short of its newline, and none — a
/// `bind` after it is read back, the torn bytes are no binding before the
/// append or after it, and the bytes the file held stand unchanged ahead of
/// the new ones. The words that close a torn line open with a space and are
/// more than the four words a binding holds.
#[test]
fn an_append_after_any_torn_last_line_is_read_back_and_the_torn_line_never_is() {
    assert!(TORN_MARK.starts_with(' ') && TORN_MARK.split_whitespace().count() > 4, "{TORN_MARK:?}");
    let (_dir, store) = store();
    fs::create_dir_all(store.root()).unwrap();
    let path = store.root().join("bindings");
    let dialed = Origin::parse("http://127.0.0.1:8642").unwrap();
    let ab = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    let a = Binding::Enrollment { origin: dialed.clone(), principal: 1, account: "1.0.1".into(), fingerprint: ab };
    let b = Binding::Enrollment { origin: dialed.clone(), principal: 7, account: "1.0.2".into(), fingerprint: ab };
    let torn = [
        Binding::Enrollment { origin: dialed.clone(), principal: 9, account: "1.0.3".into(), fingerprint: Fingerprint::parse_hex(&"cd".repeat(32)).unwrap() },
        Binding::Signed { dialed: dialed.clone(), signed: Origin::parse("https://board.example:8443").unwrap() },
    ];
    for line in torn.iter().map(ToString::to_string) {
        for cut in 0..=line.len() {
            let before = format!("{a}\n{}", &line[..cut]);
            fs::write(&path, &before).unwrap();
            assert_eq!(store.all_bindings().unwrap(), std::slice::from_ref(&a), "{:?}", &line[..cut]);
            store.bind(&b).unwrap();
            assert_eq!(store.all_bindings().unwrap(), [a.clone(), b.clone()], "{:?}", &line[..cut]);
            assert!(fs::read_to_string(&path).unwrap().starts_with(&before), "{:?}: the bytes before the append changed", &line[..cut]);
        }
    }
}

/// §3.5 as RULED (2026-10-04) — THE ONE-BINDING TEST ignores the agent
/// space's persist-first line: a claimed board's two lines (the account's
/// and its first child's) let `--principal` be omitted; a second ACCOUNT
/// bound at the same board makes the omission a halt. MUTATION 1: with the
/// first-child exclusion removed the two lines count as two principals.
#[test]
fn the_one_binding_test_ignores_the_agent_spaces_line() {
    let (_dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: fp }).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 424_242, account: "1.0.1.1".into(), fingerprint: fp }).unwrap();
    assert_eq!(store.principals_at(&origin).unwrap(), vec![1], "the agent space's line does not count");
    // A second account at the same board: two principals, the omission a halt.
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 7, account: "1.0.2".into(), fingerprint: fp }).unwrap();
    assert_eq!(store.principals_at(&origin).unwrap(), vec![7, 1]);
    // Another board's lines never count here.
    let other = Origin::parse("http://127.0.0.1:9").unwrap();
    assert!(store.principals_at(&other).unwrap().is_empty());
}

/// §3.4 — a path inside the store is recognised.
#[test]
fn a_path_inside_the_store_is_recognised() {
    let (dir, store) = store();
    store.generate(None).unwrap();
    assert!(store.contains_path(&store.root().join("anchor.skep-key")));
    assert!(store.contains_path(&store.root().join("keys").join("x.skep-key")));
    assert!(!store.contains_path(&dir.path().join("elsewhere").join("anchor.skep-key")));
}

/// §3.4 — the store is recognised under a destination the backup moment is
/// about to make, its directories created only after the check: several
/// directories not yet made beneath it, the store reached through a symlink
/// or by a path relative to the working directory, a store not yet made at
/// all; and a path beside the store — a sibling whose name begins with the
/// store's, a `..` out of it — is never inside it.
#[cfg(unix)]
#[test]
fn a_path_under_the_store_through_directories_not_yet_made_is_recognised() {
    let (dir, store) = store();
    store.generate(None).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(store.root(), &link).unwrap();
    // From the working directory up to the root, then down to the store.
    let up: PathBuf = std::env::current_dir().unwrap().components().skip(1).map(|_| Component::ParentDir).collect();
    let relative = up.join(store.root().strip_prefix("/").unwrap()).join("keys/new/deeper");
    for inside in [store.root().join("keys/new/deeper"), link.join("keys/new/anchor.skep-key"), link.join("new/deeper"), relative] {
        assert!(store.contains_path(&inside), "{} lies inside the store", inside.display());
    }
    for beside in [dir.path().join("elsewhere/new/anchor.skep-key"), dir.path().join("store-b/new"), link.join("../elsewhere/new")] {
        assert!(!store.contains_path(&beside), "{} lies beside the store", beside.display());
    }
    let fresh = FileStore::open(dir.path().join("fresh"));
    assert!(fresh.contains_path(&dir.path().join("fresh/a/b")), "a store not yet made holds what lies under it");
    assert!(!fresh.contains_path(&dir.path().join("fresher/a")));
}

/// §3.5 arm 2 — a binding whose key file is gone HALTS naming the key it
/// binds (AUTH-5.67: never a fallback): the lone device key is never signed
/// with in its place, whether the principal is named or omitted.
#[test]
fn a_binding_whose_key_file_is_gone_halts_and_never_falls_back() {
    let (_dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let bound = store.generate(Some(Label::new("bound").unwrap())).unwrap().0;
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: bound }).unwrap();
    fs::remove_file(store.key_path(&bound)).unwrap();
    store.generate(Some(Label::new("lone").unwrap())).unwrap();
    for principal in [Some(1), None] {
        let sel = KeySelector::Board { origin: &origin, principal };
        assert!(matches!(store.select(&sel, Purpose::Sign), Err(StoreError::MissingKey { fingerprint, .. }) if fingerprint == bound), "{principal:?}");
        assert!(matches!(store.signer(&sel), Err(StoreError::MissingKey { fingerprint, .. }) if fingerprint == bound), "{principal:?}");
    }
}

/// §2.2's selection test AT EVERY ARM (P11): an anchor file copied into the
/// store and bound is refused for signing however the lookup reaches it —
/// by binding, by prefix, by label — at the store's signer as at its
/// lookup, while a read of its public facts answers them.
#[test]
fn an_anchor_is_refused_for_signing_at_every_arm() {
    let (_dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    store.generate(Some(Label::new("device").unwrap())).unwrap();
    let anchor = KeyFile::new(Seed::new([8u8; 32]), true, Some(Label::new("paper-a").unwrap()), None);
    FileStore::write_once(&store.key_path(&anchor.fingerprint), anchor.to_json().as_bytes()).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 7, account: "1.0.7".into(), fingerprint: anchor.fingerprint }).unwrap();
    let prefix = anchor.fingerprint.to_hex()[..12].to_string();
    for sel in [KeySelector::Board { origin: &origin, principal: Some(7) }, KeySelector::Prefix(&prefix), KeySelector::Label("paper-a")] {
        let refused = |r: Result<(), StoreError>| matches!(r, Err(StoreError::KeyFile { error: KeyFileError::AnchorAtSigningCommand, .. }));
        assert!(refused(store.select(&sel, Purpose::Sign).map(drop)), "{sel:?} selects the anchor to sign");
        assert!(refused(store.signer(&sel).map(drop)), "{sel:?} hands out the anchor's signer");
        let facts = store.select(&sel, Purpose::Read).unwrap_or_else(|e| panic!("{sel:?}: {e}"));
        assert!(facts.anchor && facts.fingerprint == anchor.fingerprint, "{sel:?}");
    }
}

/// §3.2's reader takes no file at a hostile path's size: a key file past
/// `MAX_KEY_FILE_BYTES` is no key file, however valid its JSON — one at the
/// bound loads — and a path naming no regular file is refused before it is
/// opened, so a device answers at once rather than fill memory.
#[test]
fn a_key_file_past_its_bound_or_no_regular_file_is_refused_unread() {
    use crate::sheet::MAX_KEY_FILE_BYTES;
    let (dir, store) = store();
    let id = store.generate(None).unwrap();
    let text = fs::read_to_string(store.key_path(&id.0)).unwrap();
    let padded = |total: usize, name: &str| -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, format!("{text}{}", " ".repeat(total - text.len()))).unwrap();
        path
    };
    assert_eq!(store.load(&padded(MAX_KEY_FILE_BYTES as usize, "at.key")).unwrap().fingerprint, id.0, "a file at the bound");
    assert!(matches!(store.load(&padded(MAX_KEY_FILE_BYTES as usize + 1, "past.key")), Err(StoreError::KeyFile { error: KeyFileError::NotKeyFile, .. })));
    let sparse = dir.path().join("sparse.key");
    fs::File::create(&sparse).unwrap().set_len(64 << 20).unwrap();
    assert_eq!(crate::sheet::read_key_file(&sparse).unwrap().len() as u64, MAX_KEY_FILE_BYTES + 1, "read no further than the byte past the bound");
    #[cfg(unix)]
    assert!(matches!(store.load(Path::new("/dev/zero")), Err(StoreError::Io { .. })), "a device is no key file");
}

/// §3.3, §3.7 — a key file not yet published, `<fingerprint>.key.tmp`, is
/// never read: a listing, the device keys, §3.5 arm 3 and a `--select` of its
/// name each answer as if it were absent, and a generation stands beside it.
#[test]
fn a_key_file_not_yet_published_is_never_listed() {
    let (_dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let id = store.generate(Some(Label::new("whole").unwrap())).unwrap();
    let text = fs::read(store.key_path(&id.0)).unwrap();
    let pending = KeyFile::new(Seed::new([9u8; 32]), false, None, None).fingerprint;
    fs::write(store.root().join("keys").join(format!("{}.key.tmp", pending.to_hex())), &text[..100]).unwrap();
    assert_eq!(store.list().unwrap().iter().map(|k| k.fingerprint).collect::<Vec<_>>(), [id.0]);
    assert_eq!(store.device_keys().unwrap().iter().map(|k| k.fingerprint).collect::<Vec<_>>(), [id.0]);
    let lone = store.select(&KeySelector::Board { origin: &origin, principal: Some(1) }, Purpose::Sign).unwrap();
    assert_eq!(lone.fingerprint, id.0, "arm 3 meets the one device key");
    assert!(matches!(store.select(&KeySelector::select(&pending.to_hex()[..12]), Purpose::Read), Err(StoreError::NotFound { .. })));
    let second = store.generate(None).unwrap();
    assert_eq!(store.list().unwrap().len(), 2, "a generation stands beside it");
    assert_ne!(second.0, pending);
}

/// §3.2; AUTH-5.67 — a `keys/` file its own contents refuse stops every
/// listing of the store — `list`, the device keys, §3.5 arm 3 — as
/// `Unlistable`, and its face names the file and the act that clears it:
/// move it aside, or, for a newer skep's key, upgrade — never a generation,
/// which lists nothing and leaves the halt standing. Moved aside, the store
/// lists again.
#[test]
fn a_file_cut_short_in_the_store_halts_its_listing_naming_the_file_to_move() {
    let (dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let id = store.generate(Some(Label::new("whole").unwrap())).unwrap();
    let text = fs::read_to_string(store.key_path(&id.0)).unwrap();
    let cut = store.root().join("keys").join(format!("{}.key", "ab".repeat(32)));
    fs::write(&cut, &text[..text.len() / 2]).unwrap();
    let unlistable = |r: Result<(), StoreError>| matches!(r, Err(StoreError::Unlistable { path, error: KeyFileError::NotKeyFile }) if path == cut);
    assert!(unlistable(store.list().map(drop)), "the listing");
    assert!(unlistable(store.device_keys().map(drop)), "the device keys");
    assert!(unlistable(store.select(&KeySelector::Board { origin: &origin, principal: Some(1) }, Purpose::Sign).map(drop)), "arm 3");
    let face = Halt::from(store.list().unwrap_err()).to_string();
    assert!(face.contains(&format!("move {} out of", cut.display())), "{face}");
    assert!(!face.contains("run `skep keygen`"), "a generation lists nothing and leaves the halt standing: {face}");
    fs::rename(&cut, dir.path().join("aside.key")).unwrap();
    assert_eq!(store.list().unwrap().iter().map(|k| k.fingerprint).collect::<Vec<_>>(), [id.0], "moved aside, the store lists again");
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["v"] = serde_json::Value::from(2);
    fs::write(store.root().join("keys").join(format!("{}.key", "cd".repeat(32))), v.to_string()).unwrap();
    let newer = store.list().unwrap_err();
    assert!(matches!(newer, StoreError::Unlistable { error: KeyFileError::Newer { v: 2 }, .. }), "{newer:?}");
    let face = Halt::from(newer).to_string();
    assert!(face.contains("upgrade skep") && !face.contains("move "), "{face}");
}

/// §3.3, §3.7 — a generation the store cannot finish is `Unwritten` and
/// leaves nothing of the key: with `keys/` read-only the store holds the key
/// it held and lists it, and the face names the write and the volume's
/// room, never a "mis-pathed" key file a lookup reads.
#[cfg(unix)]
#[test]
fn a_generation_that_cannot_write_leaves_no_key_and_is_faced_as_a_write() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, store) = store();
    let first = store.generate(None).unwrap();
    let keys = store.root().join("keys");
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o500)).unwrap();
    let refused = store.generate(None);
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    let error = refused.expect_err("a read-only keys directory takes no key");
    assert!(matches!(error, StoreError::Unwritten { .. }), "{error:?}");
    let face = Halt::from(error).to_string();
    assert!(face.contains("could not write") && face.contains(&format!("free room on the volume holding {}", keys.display())), "{face}");
    assert!(!face.contains("mis-pathed"), "{face}");
    let names: Vec<String> = fs::read_dir(&keys).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(names, [format!("{}.key", first.0.to_hex())], "nothing of the refused key stands");
    assert_eq!(store.list().unwrap().len(), 1);
}
