//! THE BACKUP MOMENT (`client.md` §4.2; AUTH-5.54's order) — no daemon: the
//! file path's read-back FROM THE FILE, the destination said BEFORE the
//! write, the re-run from step 1 when the file is gone and the act named by
//! venue when the runs run out, a pair file the unlink refuses said standing
//! and never "destroyed", the paper path's re-type and dismissal and the
//! file its offer cannot destroy said standing and kept, the offer naming
//! its anchor and never its file's path, said natively just before it, the
//! label domain at the box, the one-place sentence, the store refused as a
//! destination however the path reaches it.

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

/// Checks that the destroy offer names its anchor and says its file natively.
///
/// AUTH-5.41; §4b.3: the offer is a question, which carries no rule an
/// embedder could keep it native by, so it names its anchor by its letter
/// and its label rendered inert — both boxes fixing one label that holds a
/// bidi control — and never a path or a file's name; the line just before
/// it, under AUTH-5.41, a native rule, names that anchor's file. Anchor a's
/// offer declined keeps its file and b's taken destroys it (the mutant that
/// puts the path back in the question hands the page the file's path, and
/// the one that drops the line before it asks over a file named nowhere).
#[test]
fn the_destroy_offer_names_its_anchor_and_says_the_files_path_natively_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let label = "sheet\u{202E}";
    let script = vec![Script::Label(label.into()), Script::Label(label.into()), Script::RetypeFromSheet(0), Script::YesNo(false), Script::RetypeFromSheet(1), Script::YesNo(true)];
    let mut person = Scripted::new(script);
    let out = backup_moment(&mut person, &notebook_venue(), &options(vec![a.clone(), b.clone()], true, None)).expect("the moment");
    let t = &person.transcript;
    let offers: Vec<usize> = t.iter().enumerate().filter(|(_, l)| l.starts_with("PUBLIC yes_no: ")).map(|(n, _)| n).collect();
    assert_eq!(offers.len(), 2, "one offer per verified print:\n{}", t.join("\n"));
    let tmp = dir.path().display().to_string();
    for ((&n, (letter, place)), anchor) in offers.iter().zip([("a", &a), ("b", &b)]).zip(&out.anchors) {
        let named = format!("anchor {letter} (`sheet<U+202E>`)");
        let offer = &t[n];
        assert!(offer.contains(&format!("the print of {named} passed its re-type")), "the offer names its anchor by letter and inert label: {offer}");
        assert!(!offer.contains(&tmp) && !offer.contains(".skep-key") && !offer.contains('\u{202E}'), "the offer names no path and renders its label inert: {offer}");
        let file = place.join(anchor_file_name(&anchor.label, &anchor.fingerprint));
        let before = &t[n - 1];
        assert!(before.starts_with(&format!("PUBLIC say [AUTH-5.41]: {named}: ")) && before.contains(&file.display().to_string()), "anchor {letter}'s file said just before its offer: {before}");
    }
    assert!(out.anchors[0].file.as_ref().is_some_and(|p| p.is_file()), "a's offer declined keeps its file");
    assert!(out.anchors[1].file.is_none() && files_in(&b).is_empty(), "b's offer taken destroys its file");
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

// ── THE NODE ARM (REG-4.103, REG-4.104): a registration's pairs ───────────

fn registration(board_carries_on: bool) -> Venue {
    Venue::Registration { board_carries_on }
}

/// The label boxes a moment asked, as the transcript holds them.
fn boxes(person: &Scripted) -> Vec<&String> {
    person.transcript.iter().filter(|l| l.starts_with("PUBLIC label [")).collect()
}

/// Where the first line holding `needle` stands in the transcript.
fn said_at(person: &Scripted, needle: &str) -> usize {
    person.transcript.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("`{needle}` missing from\n{}", person.transcript.join("\n")))
}

/// The cross-pair filing rule's sentence, as every saying of it carries it.
const CROSS_PAIR: &str = "EACH PLACE HOLDS ONE SHEET OF EACH PAIR, NEVER BOTH SHEETS OF ONE";

/// FENCE 1 (REG-4.103) — A FRESH REGISTRATION'S MOMENT RUNS OVER
/// BOTH PAIRS: four anchor boxes asked, each saying which pair its sheet
/// belongs to; four files exported, the org root pair's two ahead of the
/// node pair's, each to its own destination and each read back as the key
/// the outcome names, an anchor carrying no address, principal or origin;
/// the three statements once at the head, (b) counting four; and the
/// keep-the-papers line once, AUTH-5.44's create-org arm said of both pairs.
#[test]
fn a_fresh_registrations_moment_runs_over_both_pairs_four_boxes_four_files_each_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let places: Vec<PathBuf> = ["one", "two", "three", "four"].iter().map(|p| dir.path().join(p)).collect();
    let mut person = Scripted::new(vec![Script::LabelDefault; 4]);
    let out = backup_moment(&mut person, &registration(false), &options(places.clone(), false, None)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!(out.anchors.len(), 4, "two pairs, four anchors");
    let asked = boxes(&person);
    assert_eq!(asked.len(), 4, "four anchor boxes:\n{}", person.transcript.join("\n"));
    let titles = ["name the org root pair's sheet a", "name the org root pair's sheet b", "name the node pair's sheet a", "name the node pair's sheet b"];
    for (i, (asked, title)) in asked.iter().zip(titles).enumerate() {
        assert!(asked.starts_with(&format!("PUBLIC label [{title}]: ")), "box {i}: {asked}");
        let pair = if i < 2 { "This sheet belongs to your ORG'S OWN ROOT pair" } else { "This sheet belongs to your org's NODE IDENTITY's pair" };
        assert!(asked.contains(pair), "box {i} says which pair its sheet belongs to: {asked}");
        assert!(asked.contains("the only mark on it that says WHICH account it opens") && asked.contains("tell the four sheets apart"), "{asked}");
        assert!(asked.contains("rides onto a public thread, approved or DENIED, forever"), "the consequence at this door: {asked}");
    }
    for (anchor, place) in out.anchors.iter().zip(&places) {
        let path = anchor.file.clone().expect("the file stands");
        assert_eq!(path.parent(), Some(place.as_path()), "each anchor at its own destination, in the moment's order");
        let file = KeyFile::parse(&std::fs::read(&path).unwrap()).expect("a key file that reads back");
        assert!(file.anchor);
        assert_eq!((file.fingerprint, &file.public, file.label.as_deref()), (anchor.fingerprint, &anchor.public, Some(anchor.label.as_str())));
        assert_eq!((file.account, file.principal, file.origin), (None, None, None), "a registration's artifact lacks the three facts (AUTH-5.38)");
        assert_eq!(anchor.print, None);
    }
    let distinct: std::collections::HashSet<_> = out.anchors.iter().map(|a| a.fingerprint).collect();
    assert_eq!(distinct.len(), 4, "four keys");
    assert!(!out.one_place);
    let count = |needle: &str| person.transcript.iter().filter(|l| l.contains(needle)).count();
    assert_eq!((count("[AUTH-5.54 (a)]"), count("[AUTH-5.54 (b)]"), count("[AUTH-5.54 (c)]")), (1, 1, 1), "the three statements once, at the head");
    assert!(person.said("this registration founds TWO such key sets") && person.said("(b) FOUR FILES, TWO PLACES YOU CONTROL"), "{}", person.transcript.join("\n"));
    assert!(said_at(&person, "[AUTH-5.54 (c)]") < said_at(&person, "PUBLIC label ["), "the statements ahead of the boxes");
    assert_eq!(count("[AUTH-5.40]: anchor file written: "), 4, "four exports");
    assert_eq!(count("[AUTH-5.44 (create-org)]"), 1, "the keep-the-papers line once");
    let keep = &person.transcript[said_at(&person, "[AUTH-5.44 (create-org)]")];
    assert!(keep.contains("keep the anchor files — all four, one sheet of each pair to a place") && keep.contains("lose both sheets of a pair") && keep.contains("the other pair's account stands"), "said of both pairs: {keep}");
    assert_eq!(person.transcript.iter().position(|l| l.contains("[AUTH-5.44 (create-org)]")), Some(person.transcript.len() - 1), "and last, every sheet verified");
    assert!(!person.said("are in this one place"), "four places, no pair in one");
}

/// A person who removes a named anchor's file at the dismissal — after
/// every export of the run and ahead of every re-import — in each of the
/// first `runs` runs: the file the `nth` ladder words of that run named.
struct AtDismissal {
    inner: Scripted,
    nth: usize,
    runs: usize,
    named: Vec<PathBuf>,
    removed: Vec<PathBuf>,
}

impl AtDismissal {
    fn new(script: Vec<Script>, nth: usize, runs: usize) -> AtDismissal {
        AtDismissal { inner: Scripted::new(script), nth, runs, named: Vec::new(), removed: Vec::new() }
    }
}

impl Person for AtDismissal {
    fn say(&mut self, m: Public<Statement>) {
        if m.0.rule == "AUTH-5.40" && m.0.text.starts_with("anchor file written: ") {
            self.named.push(ladder_path(&m.0.text));
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
        if self.removed.len() < self.runs {
            let file = self.named[self.nth].clone();
            std::fs::remove_file(&file).expect("remove the named anchor's file");
            self.removed.push(file);
        }
        self.named.clear();
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

/// FENCE 1 (REG-4.103; §4.1 S3) — NOTHING IS ANSWERED BEFORE ALL FOUR
/// VERIFY, AND A FAILED READ-BACK TAKES EVERY FILE OF THE RUN: the fourth
/// sheet — the node pair's b — gone before its re-import in every run, the
/// three before it having read back, the moment destroys all four files of
/// each run, both pairs', saying each removal, re-runs under fresh pairs,
/// and after three runs answers nothing: a halt naming `skep register`, and
/// not one anchor file left. With the fourth gone in the first run alone,
/// the second run's four stand and are the outcome, the first run's all
/// destroyed. (The mutant that skips the fourth re-import answers an anchor
/// whose file is gone; the one that destroys the failing pair's files alone
/// leaves the org root pair's on the media.)
#[test]
fn a_fourth_sheet_that_does_not_read_back_destroys_every_file_of_the_run_and_answers_nothing() {
    let files_under = |places: &[PathBuf]| -> usize { places.iter().map(|p| files_in(p).len()).sum() };
    // The paper path, every re-type declined: the file is each anchor's
    // verified artifact, read back from the path it was written to.
    let script = |runs: usize| [vec![Script::LabelDefault; 4], vec![Script::RetypeDeclined; 4 * runs]].concat();

    // Every run's fourth file gone: three runs, then the halt.
    let dir = tempfile::tempdir().unwrap();
    let places: Vec<PathBuf> = ["one", "two", "one", "two"].iter().map(|p| dir.path().join(p)).collect();
    let mut person = AtDismissal::new(script(3), 3, 3);
    let err = backup_moment(&mut person, &registration(false), &options(places.clone(), true, None)).expect_err("every run's fourth read-back fails: nothing is answered");
    let t = person.inner.transcript.join("\n");
    let text = err.to_string();
    assert!(text.contains("could not complete") && text.contains("re-run `skep register`"), "the venue's own command: {text}");
    assert_eq!(person.removed.len(), 3, "the fourth file of each of three runs:\n{t}");
    for (run, gone) in person.removed.iter().enumerate() {
        assert!(gone.file_name().unwrap().to_string_lossy().contains("node-identity-sheet-b"), "the node pair's b: {}", gone.display());
        assert!(t.contains(&format!("the anchor file {} did not read back as the key it names (never a verified artifact): every file of this run, both pairs', is destroyed next, each said, and the moment re-runs (attempt {})", gone.display(), run + 1)), "{t}");
    }
    let destroyed: Vec<&String> = person.inner.transcript.iter().filter(|l| l.starts_with("PUBLIC say [§4.1 S3]: the anchor file ") && l.ends_with(" is destroyed")).collect();
    assert_eq!(destroyed.len(), 12, "each of the four files of each run said destroyed:\n{t}");
    for sheet in ["org-root-sheet-a", "org-root-sheet-b", "node-identity-sheet-a", "node-identity-sheet-b"] {
        assert_eq!(destroyed.iter().filter(|l| l.contains(sheet)).count(), 3, "{sheet}, once a run:\n{t}");
    }
    assert_eq!(files_under(&places[..2]), 0, "not one anchor file left, of either pair");
    assert_eq!(person.inner.transcript.iter().filter(|l| l.contains("the moment re-runs from step 1 under fresh pairs")).count(), 3, "{t}");
    assert_eq!(person.inner.transcript.iter().filter(|l| l.contains("[AUTH-5.54 (a)]")).count(), 1, "the statements once, at the head");
    assert!(!person.inner.said("[AUTH-5.44 (create-org)]"), "no keep-the-papers line of a run that verified nothing:\n{t}");
    // The three before it read back in each run, ahead of the fourth's
    // failure: each is said the verified artifact, its print declined.
    assert_eq!(person.inner.transcript.iter().filter(|l| l.contains("the print is UNVERIFIED")).count(), 9, "{t}");

    // The first run's fourth alone: the second run completes.
    let dir = tempfile::tempdir().unwrap();
    let places: Vec<PathBuf> = ["one", "two", "one", "two"].iter().map(|p| dir.path().join(p)).collect();
    let mut person = AtDismissal::new(script(2), 3, 1);
    let out = backup_moment(&mut person, &registration(false), &options(places.clone(), true, None)).unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    assert_eq!(out.anchors.len(), 4);
    assert_eq!(files_under(&places[..2]), 4, "the second run's four stand, the first run's four are gone");
    for anchor in &out.anchors {
        let path = anchor.file.clone().expect("the second run's file stands");
        assert!(!person.removed.contains(&path));
        assert_eq!(KeyFile::parse(&std::fs::read(&path).unwrap()).expect("reads back").fingerprint, anchor.fingerprint);
        assert_eq!(anchor.print, Some(Print::Unverified), "declined: the file is the verified artifact");
    }
    assert_eq!(person.inner.transcript.iter().filter(|l| l.ends_with(" is destroyed")).count(), 4, "the first run's four:\n{}", person.inner.transcript.join("\n"));
    assert_eq!(person.inner.transcript.iter().filter(|l| l.contains("[AUTH-5.44 (create-org)]")).count(), 1, "the line once, of the run that verified");
    assert_eq!(person.inner.sheets.len(), 8, "four sheets a run");
    assert_eq!(person.inner.dismissed, 2, "one dismissal a run, after all four sheets");
}

/// FENCE 2 (REG-4.103) — EACH BOX'S OFFERED DEFAULT NAMES ITS PAIR
/// AND ITS SHEET: four distinct defaults on a fresh registration — the org
/// root's sheet a and b, the node identity's sheet a and b — and two where
/// the board carries on, the node identity's alone; the host, the date and
/// the per-run token stand ahead of them, as at every door.
#[test]
fn each_registration_box_offers_a_default_naming_its_pair_and_its_sheet() {
    let tails = ["-org-root-sheet-a", "-org-root-sheet-b", "-node-identity-sheet-a", "-node-identity-sheet-b"];
    for (board_carries_on, expected) in [(false, &tails[..]), (true, &tails[2..])] {
        let dir = tempfile::tempdir().unwrap();
        let places: Vec<PathBuf> = (0..expected.len()).map(|i| dir.path().join(i.to_string())).collect();
        let mut person = Scripted::new(vec![Script::LabelDefault; expected.len()]);
        let out = backup_moment(&mut person, &registration(board_carries_on), &options(places, false, None)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
        assert_eq!(out.anchors.len(), expected.len(), "the count is of what the request generates (REG-4.104)");
        assert_eq!(boxes(&person).len(), expected.len());
        let labels: Vec<&str> = out.anchors.iter().map(|a| a.label.as_str()).collect();
        let token = labels[0].strip_prefix("testhost-2026-10-04-").and_then(|rest| rest.split('-').next()).expect("the host, the date and the run's token").to_string();
        assert_eq!(token.len(), 4, "{labels:?}");
        for (label, tail) in labels.iter().zip(expected) {
            assert_eq!(*label, format!("testhost-2026-10-04-{token}{tail}"), "the default names the pair and the sheet within it");
        }
        let distinct: std::collections::HashSet<&&str> = labels.iter().collect();
        assert_eq!(distinct.len(), expected.len(), "{labels:?}");
        if board_carries_on {
            assert!(labels.iter().all(|l| !l.contains("org-root")), "no box and no sheet of the org root's pair: {labels:?}");
            assert!(boxes(&person).iter().all(|b| b.contains("Your org root's own pair is the one your board already has")), "{:?}", boxes(&person));
            assert!(person.said("(b) TWO FILES, TWO PLACES YOU CONTROL: this registration makes one pair, the node identity's"), "{}", person.transcript.join("\n"));
        }
    }
}

/// FENCE 2 (REG-4.103) — THE CROSS-PAIR FILING RULE IS SAID AT THE
/// FILING BEAT AND AGAIN AFTER THE LABELS: each place holds one sheet of
/// each pair, never both sheets of one — once beside statement (b), ahead of
/// the first box, and once after the last box and ahead of the first export,
/// naming the sheets by the names the boxes just fixed. Where the board
/// carries on, both sayings say the two new sheets go one to each place the
/// org root's own sheets already occupy. A single-pair venue says neither.
#[test]
fn the_cross_pair_filing_rule_is_said_at_the_filing_beat_and_again_after_the_labels() {
    for board_carries_on in [false, true] {
        let anchors = if board_carries_on { 2 } else { 4 };
        let dir = tempfile::tempdir().unwrap();
        let places: Vec<PathBuf> = (0..anchors).map(|i| dir.path().join(i.to_string())).collect();
        let names = ["red", "green", "blue", "grey"];
        let mut person = Scripted::new(names[..anchors].iter().map(|n| Script::Label((*n).into())).collect());
        backup_moment(&mut person, &registration(board_carries_on), &options(places, false, None)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
        let t = &person.transcript;
        let rule: Vec<usize> = t.iter().enumerate().filter(|(_, l)| l.starts_with("PUBLIC say [REG-4.103]: ") && l.contains(CROSS_PAIR)).map(|(n, _)| n).collect();
        assert_eq!(rule.len(), 2, "said twice:\n{}", t.join("\n"));
        let asked: Vec<usize> = t.iter().enumerate().filter(|(_, l)| l.starts_with("PUBLIC label [")).map(|(n, _)| n).collect();
        assert_eq!(rule[0], said_at(&person, "[AUTH-5.54 (b)]") + 1, "at the filing beat: beside statement (b)");
        assert!(rule[0] < asked[0], "ahead of the first box");
        assert!(asked[anchors - 1] < rule[1] && rule[1] < said_at(&person, "[AUTH-5.40]"), "again after the labels, ahead of the first export:\n{}", t.join("\n"));
        let (beat, again) = (&t[rule[0]], &t[rule[1]]);
        assert!(beat.contains("THE FILING RULE IS CROSS-PAIR") && again.contains("THE FILING RULE AGAIN, now the sheets are named"), "{beat}\n{again}");
        if board_carries_on {
            assert!(beat.contains("the two new sheets go ONE TO EACH PLACE those sheets already occupy, and never both to one place"), "{beat}");
            assert!(again.contains("`red` goes to one of the places those sheets already occupy and `green` to the other, ONE TO EACH PLACE"), "{again}");
            assert!(beat.contains("your org root's own two sheets are already filed") && again.contains("your org root's own two sheets are already filed"), "{beat}\n{again}");
        } else {
            assert!(beat.contains("one org root sheet and one node sheet in each of your two places"), "{beat}");
            assert!(again.contains("`red` with `blue` in one place, `green` with `grey` in the other; never `red` beside `green`, and never `blue` beside `grey`"), "the names the boxes just fixed: {again}");
            assert!(!beat.contains("already filed") && !again.contains("already occupy"), "{beat}\n{again}");
        }
    }
    // One pair has no second pair to file across: the door-side moment says
    // (b) and no cross-pair rule.
    let dir = tempfile::tempdir().unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    backup_moment(&mut person, &Venue::DoorSide, &options(vec![dir.path().join("a"), dir.path().join("b")], false, None)).expect("the moment");
    assert!(!person.said("REG-4.103") && !person.said("CROSS-PAIR"), "{}", person.transcript.join("\n"));
}

/// FENCE 2 (REG-4.103) — THE ONE-PLACE SENTENCE IS PER PAIR: both
/// sheets of one pair in one place are warned, naming the pair; one sheet of
/// each pair in one place is the rule followed and is never warned. Four
/// sheets filed across two places say nothing; filed by pair — the sort the
/// labels teach — both pairs are warned; and where the board carries on the
/// warning says where the new sheets go.
#[test]
fn both_sheets_of_one_pair_in_one_place_are_warned_and_one_of_each_pair_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let (one, two) = (dir.path().join("one"), dir.path().join("two"));
    let run = |board_carries_on: bool, places: Vec<&PathBuf>, case: &str| {
        let sub = dir.path().join(case);
        let places: Vec<PathBuf> = places.into_iter().map(|p| sub.join(p.file_name().unwrap())).collect();
        let mut person = Scripted::new(vec![Script::LabelDefault; places.len()]);
        let out = backup_moment(&mut person, &registration(board_carries_on), &options(places, false, None)).unwrap_or_else(|h| panic!("{case}: {h}\n{}", person.transcript.join("\n")));
        let warned: Vec<String> = person.transcript.iter().filter(|l| l.contains("are in this one place")).cloned().collect();
        (out.one_place, warned)
    };
    // The rule followed: each place holds one sheet of each pair.
    let (one_place, warned) = run(false, vec![&one, &two, &one, &two], "across");
    assert!(!one_place && warned.is_empty(), "one of each pair in one place is not warned: {warned:?}");
    let (one_place, warned) = run(false, vec![&one, &two, &two, &one], "across-swapped");
    assert!(!one_place && warned.is_empty(), "{warned:?}");
    // Filed by pair: both pairs warned, each by name.
    let (one_place, warned) = run(false, vec![&one, &one, &two, &two], "by-pair");
    assert!(one_place);
    assert_eq!(warned.len(), 2, "{warned:?}");
    assert!(warned[0].starts_with("PUBLIC say [REG-4.103]: both sheets of the org root pair are in this one place") && warned[1].starts_with("PUBLIC say [REG-4.103]: both sheets of the node pair are in this one place"), "{warned:?}");
    assert!(warned[0].contains("each place holds one sheet of each pair, never both sheets of one"), "{warned:?}");
    // One pair across, the other in one place: that pair alone.
    let (one_place, warned) = run(false, vec![&one, &two, &one, &one], "node-together");
    assert!(one_place);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("both sheets of the node pair"), "{warned:?}");
    // The board carries on: the node pair's two.
    let (one_place, warned) = run(true, vec![&one, &two], "carries-on-apart");
    assert!(!one_place && warned.is_empty(), "{warned:?}");
    let (one_place, warned) = run(true, vec![&one, &one], "carries-on-together");
    assert!(one_place);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("both sheets of the node pair") && warned[0].contains("the two new sheets go one to each place your org root's own sheets already occupy"), "{warned:?}");
}

/// The registration's moment where the board carries on (REG-4.104): the
/// node pair alone — two boxes, two files, each read back — and the
/// keep-the-papers line the node pair's, naming the org root's own two
/// sheets as untouched and never to be destroyed for these (REG-4.101).
#[test]
fn a_registration_whose_board_carries_on_makes_the_node_pair_alone() {
    let dir = tempfile::tempdir().unwrap();
    let places = vec![dir.path().join("one"), dir.path().join("two")];
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let out = backup_moment(&mut person, &registration(true), &options(places.clone(), false, None)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!((out.anchors.len(), boxes(&person).len()), (2, 2), "two boxes, two sheets");
    assert_eq!(boxes(&person).iter().filter(|b| b.contains("NODE IDENTITY's pair")).count(), 2);
    for (anchor, place) in out.anchors.iter().zip(&places) {
        let file = KeyFile::parse(&std::fs::read(anchor.file.as_ref().expect("the file stands")).unwrap()).expect("reads back");
        assert_eq!((file.fingerprint, file.anchor), (anchor.fingerprint, true));
        assert_eq!(anchor.file.as_ref().and_then(|p| p.parent()), Some(place.as_path()));
    }
    assert!(person.said("said here of the node account this registration asks for"), "statement (a), keyed to the node account alone");
    let keep = &person.transcript[said_at(&person, "[AUTH-5.44 (create-org)]")];
    assert!(keep.contains("one to each place your org root's own sheets already occupy") && keep.contains("NODE IDENTITY"), "{keep}");
    assert!(keep.contains("Your org root's own two sheets are untouched by this registration") && keep.contains("never destroy them for these"), "{keep}");
    assert_eq!(person.transcript.iter().filter(|l| l.contains("[AUTH-5.44 (create-org)]")).count(), 1);
}
