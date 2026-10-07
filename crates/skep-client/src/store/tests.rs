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
    assert_eq!(sel.fingerprint, first.0);
    // Two keys, no binding: arm 4 lists both.
    let second = store.generate(Some(Label::new("two").unwrap())).unwrap();
    assert!(matches!(
        store.select(&KeySelector::Binding { origin: &origin, principal: Some(1) }, Purpose::Sign),
        Err(StoreError::NoSelection { keys }) if keys.len() == 2
    ));
    // Arm 2: the binding, and the LAST line wins.
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: first.0 }).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: second.0 }).unwrap();
    let sel = store.select(&KeySelector::Binding { origin: &origin, principal: Some(1) }, Purpose::Sign).unwrap();
    assert_eq!(sel.fingerprint, second.0, "the newest line wins");
    // `--principal` omitted where the board has exactly one binding.
    let sel = store.select(&KeySelector::Binding { origin: &origin, principal: None }, Purpose::Sign).unwrap();
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
    let bound = KeySelector::Binding { origin: &origin, principal: Some(1) };
    let facts = store.select(&bound, Purpose::Sign).unwrap();
    assert_eq!((facts.fingerprint, facts.label.as_deref(), facts.path.clone()), (id.0, Some("notebook"), store.key_path(&id.0)));
    let signer = store.signer(&bound).unwrap();
    assert_eq!((signer.fingerprint(), signer.public_key()), (facts.fingerprint, facts.public.clone()));
    let blob = signer.sign(b"bytes the library framed");
    assert!(skep_signature::verify(signer.tag(), &facts.public, b"bytes the library framed", &blob).is_ok());
    let anchor = KeyFile::new(Seed::new([6u8; 32]), true, Some("paper-b".into()), None);
    let anchor_path = dir.path().join("anchor.skep-key");
    FileStore::write_once(&anchor_path, anchor.to_json().as_bytes()).unwrap();
    assert!(matches!(store.signer(&KeySelector::Path(&anchor_path)), Err(StoreError::KeyFile { error: KeyFileError::AnchorAtSigningCommand, .. })));
}

/// §4.3 — the persist-first line read back: the LAST line naming the
/// account at the board answers its id; another account's or another
/// board's lines answer nothing.
#[test]
fn the_persisted_id_is_the_last_line_naming_the_account() {
    let (_dir, store) = store();
    let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
    let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    assert_eq!(store.persisted_id(&origin, "1.0.1.1").unwrap(), None);
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 1, account: "1.0.1".into(), fingerprint: fp }).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 424_242, account: "1.0.1.1".into(), fingerprint: fp }).unwrap();
    store.bind(&Binding::Enrollment { origin: origin.clone(), principal: 525_252, account: "1.0.1.1".into(), fingerprint: fp }).unwrap();
    assert_eq!(store.persisted_id(&origin, "1.0.1.1").unwrap(), Some(525_252), "the newest line wins");
    assert_eq!(store.persisted_id(&origin, "1.0.1.2").unwrap(), None);
    assert_eq!(store.persisted_id(&Origin::parse("http://127.0.0.1:9").unwrap(), "1.0.1.1").unwrap(), None);
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
    assert_eq!(enroll.line(), format!("http://127.0.0.1:8642 7 1.0.1 {}", "ab".repeat(32)));
    assert_eq!(Binding::parse_line(&enroll.line()), Some(enroll.clone()));
    let sline = Binding::Signed { dialed: dialed.clone(), signed: signed.clone() };
    assert_eq!(sline.line(), "signed http://127.0.0.1:8642 https://board.example");
    assert_eq!(Binding::parse_line(&sline.line()), Some(sline.clone()));
    assert_eq!(Binding::parse_line("retired abab"), None, "no third form");
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
    assert_eq!(warning.line, b.line());
    assert!(warning.to_string().ends_with(&format!("record this binding line yourself: {}", b.line())), "{warning}");
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
