//! The store (`client.md` §3): the modes, `O_EXCL`, the doctored files'
//! refusals, the lookup's arms, the two line forms, the lock.

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

/// AUTH-1.24/1.25 at the box: 128 bytes admitted, 129 refused with the byte
/// count named (AUTH-2.96's vector row), a newline refused, the empty label
/// faced (AUTH-5.42).
#[test]
fn the_label_domain_is_tested_at_the_box() {
    assert!(Label::new(&"a".repeat(128)).is_ok());
    assert_eq!(Label::new(&"a".repeat(129)).unwrap_err(), LabelFault::TooLong { bytes: 129 });
    assert_eq!(Label::new("two\nlines").unwrap_err(), LabelFault::Newline);
    assert_eq!(Label::new("").unwrap_err(), LabelFault::Empty);
    assert!(Label::new("my phone ").is_ok(), "a trailing space is in the domain");
    assert_eq!(Label::new("Paper A / 2026").unwrap().slug(), "paper-a-2026");
    // Bytes, not characters: 43 three-byte characters are 129 bytes.
    assert_eq!(Label::new(&"€".repeat(43)).unwrap_err(), LabelFault::TooLong { bytes: 129 });
}

/// §3.3 — the directory `0700`, the file `0600`; §3.7 — a second `keygen`
/// makes a second file under `O_EXCL` and never rewrites the first.
#[test]
fn generate_writes_once_under_the_modes() {
    let (_dir, store) = store();
    let a = store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let b = store.generate(None).unwrap();
    assert_ne!(a, b);
    let keys = store.list().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| !k.anchor));
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
    let anchor = KeyFile::new(Seed::new([5u8; 32]), true, Some("paper-a".into()), None);
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
        store.select(&KeySelector::Binding { origin: &origin, principal: Some(1) }, Purpose::Sign),
        Err(StoreError::NoSelection { keys }) if keys.is_empty()
    ));
    // Arm 3: exactly one device key.
    let first = store.generate(Some(Label::new("one").unwrap())).unwrap();
    let sel = store.select(&KeySelector::Binding { origin: &origin, principal: Some(1) }, Purpose::Sign).unwrap();
    assert_eq!(sel.file.fingerprint, first.0);
    // Two keys, no binding: arm 4 lists both.
    let second = store.generate(Some(Label::new("two").unwrap())).unwrap();
    assert!(matches!(
        store.select(&KeySelector::Binding { origin: &origin, principal: Some(1) }, Purpose::Sign),
        Err(StoreError::NoSelection { keys }) if keys.len() == 2
    ));
    // Arm 2: the binding, and the LAST line wins.
    store.bind(&Binding::Enrolment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: first.0 }).unwrap();
    store.bind(&Binding::Enrolment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: second.0 }).unwrap();
    let sel = store.select(&KeySelector::Binding { origin: &origin, principal: Some(1) }, Purpose::Sign).unwrap();
    assert_eq!(sel.file.fingerprint, second.0, "the newest line wins");
    // `--principal` omitted where the board has exactly one binding.
    let sel = store.select(&KeySelector::Binding { origin: &origin, principal: None }, Purpose::Sign).unwrap();
    assert_eq!(sel.file.fingerprint, second.0);
    // Arm 1: a path, no lookup.
    let sel = store.select(&KeySelector::Path(&store.key_path(&first.0)), Purpose::Sign).unwrap();
    assert_eq!(sel.file.fingerprint, first.0);
    // `--select` by shape: a prefix, a label, an ambiguity listed and never
    // picked.
    let prefix = &first.0.to_hex()[..12];
    assert_eq!(store.select(&KeySelector::select(prefix), Purpose::Read).unwrap().file.fingerprint, first.0);
    assert_eq!(store.select(&KeySelector::select("two"), Purpose::Read).unwrap().file.fingerprint, second.0);
    assert!(matches!(store.select(&KeySelector::select("zz"), Purpose::Read), Err(StoreError::NotFound { .. })));
    store.generate(Some(Label::new("two").unwrap())).unwrap();
    assert!(matches!(store.select(&KeySelector::select("two"), Purpose::Read), Err(StoreError::Ambiguous { keys }) if keys.len() == 2));
}

/// §3.5 — the two line forms and no third; §3.7 — a final line without
/// `\n` is ignored, the signed line is keyed by the origin DIALED.
#[test]
fn the_bindings_file_has_two_line_forms() {
    let (_dir, store) = store();
    let dialed = Origin::parse("http://127.0.0.1:8642").unwrap();
    let signed = Origin::parse("https://board.example").unwrap();
    let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    let enrol = Binding::Enrolment { origin: dialed.clone(), principal: 7, account: "1.0.1".into(), fingerprint: fp };
    assert_eq!(enrol.line(), format!("http://127.0.0.1:8642 7 1.0.1 {}", "ab".repeat(32)));
    assert_eq!(Binding::parse_line(&enrol.line()), Some(enrol.clone()));
    let sline = Binding::Signed { dialed: dialed.clone(), signed: signed.clone() };
    assert_eq!(sline.line(), "signed http://127.0.0.1:8642 https://board.example");
    assert_eq!(Binding::parse_line(&sline.line()), Some(sline.clone()));
    assert_eq!(Binding::parse_line("retired abab"), None, "no third form");
    store.bind(&enrol).unwrap();
    store.bind(&sline).unwrap();
    assert_eq!(store.bindings(&dialed).unwrap().len(), 2);
    assert_eq!(store.signed_origin_for(&dialed).unwrap(), Some(signed));
    assert_eq!(store.enrolment_for(&dialed, 7).unwrap(), Some(("1.0.1".to_string(), fp)));
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
    let b = Binding::Enrolment { origin, principal: 1, account: "1.0.1".into(), fingerprint: fp };
    let err = store.bind(&b).unwrap_err();
    fs::set_permissions(store.root(), fs::Permissions::from_mode(0o700)).unwrap();
    match err {
        StoreError::ReadOnly { line, .. } => assert_eq!(line, b.line()),
        other => panic!("not a warning: {other}"),
    }
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
