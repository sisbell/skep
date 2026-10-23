//! THE BACKUP MOMENT (`client.md` §4.2; AUTH-5.54's order) — no daemon: the
//! file path's read-back FROM THE FILE, the destination said BEFORE the
//! write, the re-run from step 1 when the file is gone and the act named by
//! venue when the runs run out, a pair file the unlink refuses said standing
//! and never "destroyed", the paper path's re-type and dismissal and the
//! file its offer cannot destroy said standing and kept, the label domain
//! at the box, the one-place sentence, the store refused as a destination
//! however the path reaches it.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use skep_client::ceremony::backup::{anchor_file_name, backup_moment, BackupOptions, Print, Venue};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};
use skep_client::sheet::{Facts, KeyFile, Label};
use skep_client::Origin;

use crate::common::{files_in, Hooked};

fn options(destinations: Vec<PathBuf>, paper: bool, store: Option<PathBuf>) -> BackupOptions {
    BackupOptions { labels: vec![], destinations, paper, store, host_name: "testhost".into(), date: "2026-10-04".into() }
}

fn notebook_venue() -> Venue {
    Venue::Notebook { facts: Facts { account: "1.0.1".into(), principal: 1, origin: Origin::parse("http://127.0.0.1:8642").unwrap() } }
}

/// The file form (the DEFAULT): each anchor exported once to its own
/// destination, named `anchor-<slug>-<8 hex>.skep-key`, mode 0600, READ BACK
/// FROM THE FILE and verified locally; the statements keyed to the venue; no
/// sheet, no dismissal.
#[test]
fn the_file_path_reads_each_anchor_back_from_its_file() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let out = backup_moment(&mut person, &Venue::DoorSide, &options(vec![a.clone(), b.clone()], false, None)).expect("the moment");
    assert_eq!(out.anchors.len(), 2);
    assert!(!out.one_place);
    for (i, anchor) in out.anchors.iter().enumerate() {
        let path = anchor.file.clone().expect("the file stands");
        assert_eq!(path.parent(), Some([&a, &b][i].as_path()));
        assert_eq!(path.file_name().unwrap().to_string_lossy(), anchor_file_name(&anchor.label, &anchor.fingerprint));
        let file = KeyFile::parse(&std::fs::read(&path).unwrap()).expect("a key file");
        assert!(file.anchor);
        assert_eq!((file.fingerprint, &file.public, file.label.as_deref()), (anchor.fingerprint, &anchor.public, Some(anchor.label.as_str())));
        assert_eq!((file.account, file.principal, file.origin), (None, None, None), "the door-side artifact lacks the three facts (AUTH-5.38)");
        let suffix = if i == 0 { "-a" } else { "-b" };
        assert!(anchor.label.as_str().starts_with("testhost-2026-10-04-") && anchor.label.as_str().ends_with(suffix), "{}", anchor.label);
        assert_eq!(anchor.print, None, "the file form prints nothing");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    assert_ne!(out.anchors[0].fingerprint, out.anchors[1].fingerprint);
    assert!(person.sheets.is_empty() && person.dismissed == 0, "the file form shows no seed");
    assert!(person.said("AUTH-5.54 (a)") && person.said("on the board you are joining another party runs the daemon"), "the door-side operator sentence");
    assert!(person.said("TWO FILES, TWO PLACES YOU CONTROL"));
    assert!(person.said("AUTH-5.54 (c)") && person.said("DESTROYED IS NOT LOST"));
    assert!(person.said("name anchor a") && person.said("name anchor b"));
    assert!(person.said("names the SHEET and never where you keep it"));
    assert!(person.said("AUTH-5.40") && person.said("move it to media you control") && !person.said("keep the print"), "the ladder words, file form");
    assert!(person.said("AUTH-5.44 (create-org)") && person.said("keep the anchor files"), "the per-site line");
}

/// The path the ladder words name.
fn ladder_path(text: &str) -> PathBuf {
    text.strip_prefix("anchor file written: ").and_then(|t| t.split(" — ").next()).map(PathBuf::from).expect("the path in the ladder words")
}

/// A person who removes the FIRST anchor's file once it stands — at the
/// second anchor's ladder words, said before that anchor's write and after
/// the first's — so it is gone before its read-back, once.
struct Vanisher {
    inner: Scripted,
    named: Option<PathBuf>,
    removed: Option<PathBuf>,
}

impl Person for Vanisher {
    fn say(&mut self, m: Public<Statement>) {
        if m.0.rule == "AUTH-5.40" && self.removed.is_none() {
            let path = ladder_path(&m.0.text);
            match self.named.take() {
                None => self.named = Some(path),
                Some(first) => {
                    std::fs::remove_file(&first).expect("remove the first anchor's file");
                    self.removed = Some(first);
                }
            }
        }
        self.inner.say(m);
    }
    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
        self.inner.label(m)
    }
    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
        self.inner.ask(m)
    }
    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
        self.inner.yes_no(m)
    }
    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned> {
        self.inner.sheet(m)
    }
    fn dismiss(&mut self) {
        self.inner.dismiss()
    }
    fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        self.inner.retype(m)
    }
    fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned> {
        self.inner.destination(m)
    }
    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        self.inner.confirm_typed(m)
    }
    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned> {
        self.inner.import(m)
    }
    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned> {
        self.inner.kept_or_placed(m)
    }
}

/// §4.1 S3: a file that does not read back RE-RUNS THE MOMENT FROM STEP 1
/// under a fresh pair, the bad run's files destroyed — the read-back is
/// FROM THE FILE, over the disk channel whose absence breaks it.
/// MUTATION 3: with the read-back removed the outcome names a file that is
/// not there and this test fails.
#[test]
fn a_file_gone_before_its_read_back_re_runs_the_moment_from_step_one() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let mut person = Vanisher { inner: Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]), named: None, removed: None };
    let out = backup_moment(&mut person, &Venue::DoorSide, &options(vec![a.clone(), b.clone()], false, None)).expect("the moment completes on its second run");
    let removed = person.removed.clone().expect("a file was removed");
    assert!(person.inner.said("did not read back as the key it names") && person.inner.said("re-runs from step 1"), "{}", person.inner.transcript.join("\n"));
    assert!(person.inner.said(&format!("the anchor file {} is destroyed", removed.display())), "a file gone before its removal is destroyed:\n{}", person.inner.transcript.join("\n"));
    for anchor in &out.anchors {
        let path = anchor.file.clone().expect("the second run's file stands");
        assert_ne!(path, removed);
        let file = KeyFile::parse(&std::fs::read(&path).unwrap()).expect("reads back");
        assert_eq!(file.fingerprint, anchor.fingerprint);
    }
    assert_eq!(files_in(&a).len(), 1, "the first run's a is gone, the second's stands");
    assert_eq!(files_in(&b).len(), 1, "the first run's b was destroyed with its pair");
    assert_eq!(person.inner.transcript.iter().filter(|l| l.contains("AUTH-5.40")).count(), 4, "two exports per run, two runs");
    assert_eq!(person.inner.transcript.iter().filter(|l| l.contains("AUTH-5.54 (a)")).count(), 1, "the statements are said once, at the head");
}

/// A moment whose read-back fails run after run names the command that
/// re-runs it AT ITS VENUE (§4.2; §4c.1) — the recipient's beat its own and
/// the door-side form its own, never the claim's.
#[test]
fn a_moment_whose_runs_run_out_names_its_venues_own_command() {
    let handoff = Venue::Handoff { facts: Facts { account: "1.0.1.2".into(), principal: 7, origin: Origin::parse("http://127.0.0.1:8642").unwrap() }, operator: "the giver runs this board".into() };
    for (venue, command) in [(handoff, "`skep accept`"), (Venue::DoorSide, "`skep keygen --anchors`"), (notebook_venue(), "`skep claim`")] {
        let dir = tempfile::tempdir().unwrap();
        let mut person = Hooked::new(vec![Script::LabelDefault, Script::LabelDefault]);
        // Every run's anchor a is gone before its read-back: removed at
        // anchor b's ladder words, once a's file stands.
        let mut pending: Option<PathBuf> = None;
        person.on_say = Box::new(move |rule, text| {
            if rule == "AUTH-5.40" && text.starts_with("anchor file written: ") {
                let path = ladder_path(text);
                if let Some(a) = pending.take() {
                    std::fs::remove_file(&a).expect("remove anchor a");
                } else if path.file_name().is_some_and(|n| n.to_string_lossy().contains("-a-")) {
                    pending = Some(path);
                }
            }
        });
        let err = backup_moment(&mut person, &venue, &options(vec![dir.path().join("a"), dir.path().join("b")], false, None)).expect_err("every read-back fails");
        let text = err.to_string();
        assert!(text.contains("could not complete") && text.contains(&format!("re-run {command}")), "{command}: {text}");
    }
}

/// §4.2 — THE DESTINATION IS SAID BEFORE THE WRITE: at each anchor's ladder
/// words the path they name holds no file yet, and once the moment is done
/// every path so named holds the anchor the outcome names — so a run killed
/// inside the write leaves a file the words already named (the mutant that
/// says the words after the write names a file a kill leaves unsaid).
#[test]
fn the_destination_is_said_before_the_file_exists() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let named: Rc<RefCell<Vec<PathBuf>>> = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&named);
    let mut person = Hooked::new(vec![Script::LabelDefault, Script::LabelDefault]);
    person.on_say = Box::new(move |rule, text| {
        if rule == "AUTH-5.40" && text.starts_with("anchor file written: ") {
            let path = ladder_path(text);
            assert!(!path.exists(), "{}: the file stands before its words are said", path.display());
            seen.borrow_mut().push(path);
        }
    });
    let out = backup_moment(&mut person, &Venue::DoorSide, &options(vec![a, b], false, None)).expect("the moment");
    let named = named.borrow();
    assert_eq!(named.len(), 2, "one line per anchor");
    for (anchor, path) in out.anchors.iter().zip(named.iter()) {
        assert_eq!(anchor.file.as_deref(), Some(path.as_path()), "the outcome names the path the words named");
        assert!(path.is_file(), "{}: written after its words", path.display());
    }
    assert!(person.inner.said("written as these words are said"), "{}", person.inner.transcript.join("\n"));
}

/// AUTH-5.40; §4.1 S3 — A PAIR FILE THE UNLINK REFUSES after a failed
/// read-back is said STANDING by its path, never "destroyed": anchor a's
/// file damaged and its directory sealed against the unlink before the
/// read-back, the moment says a's path could not be destroyed and still
/// stands, says b's destroyed, and re-runs; the directory taking writes
/// again, the second run completes beside the file that stands (the mutant
/// that drops the unlink's answer says nothing of a seed left on the media).
#[cfg(unix)]
#[test]
fn a_pair_file_the_unlink_refuses_is_said_standing_never_destroyed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let mut person = Hooked::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let a_dir = a.clone();
    let mut first: Option<PathBuf> = None;
    let mut sealed = false;
    person.on_say = Box::new(move |rule, text| {
        if rule == "AUTH-5.40" && text.starts_with("anchor file written: ") && !sealed {
            let path = ladder_path(text);
            match first.take() {
                None => first = Some(path),
                Some(a_file) => {
                    // Anchor a's file stands: damaged, and its directory
                    // sealed against the unlink.
                    std::fs::write(&a_file, b"{\"type\":\"skep-key\"").unwrap();
                    std::fs::set_permissions(&a_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
                    sealed = true;
                }
            }
        }
        if rule == "§4.1 S3" && text.contains("re-runs from step 1 under a fresh pair") {
            std::fs::set_permissions(&a_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    });
    let out = backup_moment(&mut person, &Venue::DoorSide, &options(vec![a.clone(), b.clone()], false, None));
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = out.unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    let t = person.inner.transcript.join("\n");
    let (a_name, b_name) = (a.display().to_string(), b.display().to_string());
    let standing = person.inner.transcript.iter().find(|l| l.contains("could not be destroyed")).unwrap_or_else(|| panic!("the standing file is said:\n{t}"));
    assert!(standing.contains(&a_name) && standing.contains("STILL STANDS"), "{standing}");
    assert!(person.inner.transcript.iter().any(|l| l.contains("is destroyed") && l.contains(&b_name)), "b's file destroyed, said:\n{t}");
    assert!(!person.inner.transcript.iter().any(|l| l.contains("is destroyed") && l.contains(&a_name)), "never 'destroyed' of a file that stands:\n{t}");
    assert_eq!(files_in(&a).len(), 2, "the damaged file stands beside the second run's");
    assert_eq!(files_in(&b).len(), 1, "the first run's b destroyed, the second's stands");
    assert!(out.anchors.iter().all(|x| x.file.as_ref().is_some_and(|p| p.is_file())));
}

/// AUTH-5.41; AUTH-5.40 — THE FILE THE OFFER CANNOT DESTROY is said STANDING
/// by its path and kept as the artifact: anchor a's directory sealed against
/// the unlink by the time its print passes, "destroy the file and keep the
/// print" answered yes leaves the file, said, and the outcome still names
/// it; anchor b's offer declined keeps its file as before (the mutant that
/// drops the unlink's answer tells the person a seed is gone that is not).
#[cfg(unix)]
#[test]
fn a_file_the_offer_cannot_destroy_is_said_standing_and_kept() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let script = vec![Script::LabelDefault, Script::LabelDefault, Script::RetypeFromSheet(0), Script::YesNo(true), Script::RetypeFromSheet(1), Script::YesNo(false)];
    let mut person = Hooked::new(script);
    let a_dir = a.clone();
    let mut words = 0;
    person.on_say = Box::new(move |rule, text| {
        if rule == "AUTH-5.40" && text.starts_with("anchor file written: ") {
            words += 1;
            if words == 2 {
                std::fs::set_permissions(&a_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            }
        }
    });
    let out = backup_moment(&mut person, &notebook_venue(), &options(vec![a.clone(), b.clone()], true, None));
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = out.unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    let t = person.inner.transcript.join("\n");
    let a_file = out.anchors[0].file.clone().expect("the file the volume kept stands in the outcome");
    assert!(a_file.is_file() && out.anchors[0].print == Some(Print::Verified));
    let a_name = a_file.display().to_string();
    let standing = person.inner.transcript.iter().find(|l| l.contains("could not be destroyed")).unwrap_or_else(|| panic!("the standing file is said:\n{t}"));
    assert!(standing.contains(&a_name) && standing.contains("STILL STANDS"), "{standing}");
    assert!(!person.inner.said(&format!("the file {a_name} is destroyed")), "never 'destroyed' of a file that stands:\n{t}");
    assert!(out.anchors[1].file.as_ref().is_some_and(|p| p.is_file()), "b's offer declined keeps its file");
    assert_eq!(files_in(&a).len() + files_in(&b).len(), 2);
}

/// THE PAPER PATH (`--paper`): the sheets shown after the export, DISMISSED
/// before the re-type, the 64 hex typed back from THAT sheet — a wrong
/// re-type says "re-scan" and asks again — then AUTH-5.41's offer where the
/// print passed; a declined re-type leaves the print UNVERIFIED and the file
/// the kept artifact.
#[test]
fn the_paper_path_retypes_from_the_sheet_between_a_dismissal_and_the_offer() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let script = vec![
        Script::LabelDefault,
        Script::LabelDefault,
        Script::RetypeWrong,
        Script::RetypeFromSheet(0),
        Script::YesNo(false),
        Script::RetypeFromSheet(1),
        Script::YesNo(true),
    ];
    let mut person = Scripted::new(script);
    let out = backup_moment(&mut person, &notebook_venue(), &options(vec![a.clone(), b.clone()], true, None)).expect("the moment");
    assert_eq!(person.sheets.len(), 2, "both sheets shown");
    assert_eq!(person.dismissed, 1, "dismissed once, between the print and the re-type");
    let t = &person.transcript;
    let at = |needle: &str| t.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("{needle} missing from\n{}", t.join("\n")));
    assert!(at("AUTH-5.40") < at("SECRET sheet"), "export before the print");
    assert!(at("SECRET sheet") < at("SECRET dismiss") && at("SECRET dismiss") < at("SECRET retype"), "print, dismiss, re-type");
    assert!(person.said("this is not the key on this paper — re-scan"));
    assert!(person.said("PRINT TWO, KEEP THEM APART"), "(b) keyed to the paper path");
    assert!(person.said("or destroy it and keep the print"), "the ladder's print clause under --paper");
    assert!(out.anchors[0].print == Some(Print::Verified) && out.anchors[0].file.as_ref().is_some_and(|p| p.is_file()), "a: verified, the file kept");
    assert!(out.anchors[1].print == Some(Print::Verified) && out.anchors[1].file.is_none(), "b: verified, the file destroyed on the offer");
    assert_eq!(files_in(&b).len(), 0);
    assert!(person.transcript.iter().any(|l| l.contains("[AUTH-5.41]") && l.contains("is destroyed")), "the destruction said after the act:\n{}", t.join("\n"));
    assert!(person.said("AUTH-5.44 (notebook)") && person.said("keep the papers apart"), "the notebook form, 'papers'");
    for sheet in &person.sheets {
        assert_eq!((sheet.account.as_deref(), sheet.principal, sheet.origin.as_deref()), (Some("1.0.1"), Some(1), Some("http://127.0.0.1:8642")), "the notebook artifact carries the three facts");
        assert_eq!(sheet.seed_grouped.as_str().split_whitespace().count(), 8, "8 groups of 8 (AUTH-5.1)");
        assert_eq!(sheet.seed_grouped.as_str().lines().count(), 2, "4 groups per line");
    }

    // Declined: the print UNVERIFIED, the file the verified artifact, never
    // destroyed in its favour.
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault, Script::RetypeDeclined, Script::RetypeDeclined]);
    let out = backup_moment(&mut person, &notebook_venue(), &options(vec![a, b], true, None)).expect("the moment");
    assert!(out.anchors.iter().all(|x| x.print == Some(Print::Unverified) && x.file.as_ref().is_some_and(|p| p.is_file())));
    assert!(person.said("the print is UNVERIFIED") && person.said("never destroyed in favor of an unverified one"));
}

/// AUTH-1.24's domain, tested AT THE BOX (P13): 129 bytes refused, 128
/// admitted, a line break refused, the box re-asked.
#[test]
fn the_label_domain_is_tested_at_the_box_and_the_box_re_asked() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let long129 = "x".repeat(129);
    let long128 = "y".repeat(128);
    let mut person = Scripted::new(vec![Script::Label(long129), Script::Label(long128.clone()), Script::Label("two\nlines".into()), Script::Label("".into()), Script::Label("sheet b".into())]);
    let out = backup_moment(&mut person, &Venue::DoorSide, &options(vec![a, b], false, None)).expect("the moment");
    assert_eq!(out.anchors[0].label.as_str(), long128);
    assert_eq!(out.anchors[1].label.as_str(), "sheet b");
    assert_eq!(person.transcript.iter().filter(|l| l.contains("[AUTH-1.24]") && l.contains("refused at the box")).count(), 3, "{}", person.transcript.join("\n"));
    assert!(person.said("129 bytes") || person.said("more than 128"), "{}", person.transcript.join("\n"));
    assert!(Label::new(&"€".repeat(43)).is_err(), "43 three-byte characters are 129 bytes");
    assert!(Label::new(&"€".repeat(42)).is_ok());
}

/// Both anchors in ONE place: admitted and SAID (AUTH-5.54 (b)); a path
/// inside the key store: refused (§3.4), by flag and at the prompt alike.
#[test]
fn one_place_is_said_and_the_store_is_refused_as_a_destination() {
    let dir = tempfile::tempdir().unwrap();
    let one = dir.path().join("one");
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let out = backup_moment(&mut person, &Venue::DoorSide, &options(vec![one.clone(), one.clone()], false, None)).expect("the moment");
    assert!(out.one_place);
    assert!(person.said("both anchors are in this one place"));
    assert_eq!(files_in(&one).len(), 2);

    let store = dir.path().join("store");
    std::fs::create_dir_all(store.join("keys")).unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let err = backup_moment(&mut person, &Venue::DoorSide, &options(vec![store.join("keys"), dir.path().join("b")], false, Some(store.clone()))).expect_err("refused");
    assert!(err.to_string().contains("lies inside the key store"), "{err}");
    assert_eq!(files_in(&store.join("keys")).len(), 0, "nothing written under the store");

    // At the prompt: the inside path is said and asked again, no default.
    let outside = dir.path().join("outside");
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault, Script::Destination(store.join("keys")), Script::Destination(outside.clone()), Script::Destination(outside.clone())]);
    let out = backup_moment(&mut person, &Venue::DoorSide, &options(vec![], false, Some(store))).expect("the moment");
    assert!(person.said("that path lies inside the key store"));
    assert!(out.one_place);
    assert!(person.said("no default is offered"), "SECRET destination prompt");
    assert_eq!(files_in(&outside).len(), 2);
    assert!(Path::new(&outside).is_dir());
}

/// §3.4 however the destination reaches the store — under directories the
/// moment is about to make, or through a symlink to it: refused before
/// anything is made or written there, or anywhere.
#[cfg(unix)]
#[test]
fn the_store_is_refused_as_a_destination_however_the_path_reaches_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    std::fs::create_dir_all(store.join("keys")).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&store, &link).unwrap();
    let elsewhere = dir.path().join("b");
    for (inside, made) in [(store.join("keys/new/a"), store.join("keys/new")), (link.join("x/y"), store.join("x"))] {
        let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
        let err = backup_moment(&mut person, &Venue::DoorSide, &options(vec![inside.clone(), elsewhere.clone()], false, Some(store.clone()))).expect_err("refused");
        assert!(err.to_string().contains("lies inside the key store"), "{}: {err}", inside.display());
        assert!(!made.exists(), "{} was made under the store", made.display());
    }
    assert!(files_in(&store.join("keys")).is_empty() && !elsewhere.exists(), "nothing written");
}
