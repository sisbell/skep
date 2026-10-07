//! `recover --anchor-lost` — THE LOSS ARM, L0–L7 (`client.md` §4a.6;
//! AUTH-5.59's LOSS arm; AUTH-5.47): every enrolled anchor shown with the
//! record that enrolled it, the finder question (P27), two fresh boxes
//! prefilled from the LOST paper's label, the SURVIVING paper imported and
//! its session opened, a fresh pair exported under AUTH-5.54 steps 1–3 and
//! enrolled as ONE anchor-flagged record, each fresh anchor re-imported from
//! its artifact and probed (step 3's failure arm retiring a pair whose
//! private half exists nowhere and re-running under a fresh one), the
//! supersession trail from the lost anchor's enroll link to the new pair's,
//! the lost anchor retired — on the race arm every key enrolled since L0
//! too — and the end face. The device arm's helpers it shares are its
//! parent's.

use skep_identity::{Enrollment, Fingerprint, PublicKey};

use super::{abandoned, reread, retire_one, row_text, RecoverOptions, Recovered};
use crate::board::{Board, Scope};
use crate::ceremony::backup::{export_pair, reimport_anchor, two_places, AnchorArtifact, BackupOptions};
use crate::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome};
use crate::ceremony::first_session::{first_session, FirstSessionReads};
use crate::ceremony::handshake::{handshake, Site};
use crate::ceremony::import::{import_anchor, no_artifact_face, whose_account, ImportContext, ImportOutcome, ImportedAnchor, Whose};
use crate::ceremony::preview::PreviewSite;
use crate::ceremony::reads::{r0, Act};
use crate::ceremony::say;
use crate::ceremony::trail::Trail;
use crate::derive::records::{credential_records, Hand};
use crate::halt::Halt;
use crate::person::{LabelBox, Person, Public, Question};
use crate::sheet::{render_inert, Facts, KeyFile, Label};
use crate::store::{FileStore};

/// THE LOSS ARM, L0–L7 (`client.md` §4a.6; AUTH-5.59's LOSS arm; AUTH-5.47).
pub(super) fn loss_arm(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &RecoverOptions) -> Result<Recovered, Halt> {
    let own: Vec<(Fingerprint, PublicKey)> = store.device_keys()?.iter().map(|k| (k.fingerprint, k.public.clone())).collect();
    let held: Vec<Fingerprint> = own.iter().map(|(f, _)| *f).collect();
    // L0: R0, and the arm's precondition off the flags.
    let reads = r0(board, person, opts.principal, Act::Enrollment, &own)?;
    let account = reads.account.clone();
    let anchors: Vec<Fingerprint> = reads.walk.set.enrolled.iter().filter(|e| e.anchor).map(|e| e.fingerprint).collect();
    if anchors.is_empty() {
        return Err(Halt::face(format!("no anchor is enrolled at {}", reads.walk.set_account), "AUTH-5.16's second arm: no paper exists to lose or to survive", "the loss arm does not run here"));
    }
    say(person, "AUTH-5.47", "LOSS IS NOT RETIREMENT: until this arm runs the lost paper OUTRANKS EVERY DEVICE SESSION PERMANENTLY, and one paper stands between this account and the both-lost state — this is the only recovery from a single anchor's loss this design has");
    // Every enrolled anchor, with the record that enrolled it.
    let shown: Vec<String> = anchors
        .iter()
        .map(|fp| {
            let rec = reads.records.enrollment_of(fp);
            let by = match rec {
                Some(r) => match (&r.hand, r.position) {
                    (Hand::Key(h), Some(at)) => format!("enrolled at position {at} by {h} ({})", reads.records.label_of(h).map(|l| render_inert(&l)).unwrap_or_default()),
                    (Hand::Bare, Some(at)) => format!("the genesis, at position {at}"),
                    (_, None) => "enrolled by the genesis (position-free below the floor; no hand asserted)".into(),
                    _ => "enrolled; the hand not readable here".into(),
                },
                None => "no enrolling record found".into(),
            };
            format!("{} — {by}", row_text(fp, &reads.records))
        })
        .collect();
    say(person, "AUTH-5.59 step 1", format!("ENROLLED ANCHORS:\n  {}", shown.join("\n  ")));
    // The surviving file's fingerprint, peeked off its public members for
    // the default.
    let surviving_peek: Option<KeyFile> = opts.anchor.as_deref().and_then(|p| std::fs::read(p).ok()).and_then(|b| KeyFile::parse(&b).ok());
    let lost_fp: Fingerprint = if let Some(prefix) = opts.lost.first() {
        let prefix = prefix.trim().to_ascii_lowercase();
        let matches: Vec<&Fingerprint> = anchors.iter().filter(|f| f.to_hex().starts_with(&prefix)).collect();
        match matches.as_slice() {
            [one] => **one,
            [] => {
                if reads.walk.set.enrolled.iter().any(|e| !e.anchor && e.fingerprint.to_hex().starts_with(&prefix)) {
                    return Err(Halt::face(format!("`{prefix}` names a DEVICE key"), "the loss arm retires a PAPER; a device key's loss is the device arm's (`skep recover` without `--anchor-lost`)", "name the lost anchor's prefix"));
                }
                return Err(Halt::face(format!("no enrolled anchor starts with `{prefix}`"), format!("the anchors: {}", anchors.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", ")), "name the lost anchor's prefix"));
            }
            _ => return Err(Halt::face(format!("`{prefix}` matches more than one anchor"), "give a longer prefix", "never a pick")),
        }
    } else {
        let candidates: Vec<&Fingerprint> = anchors.iter().filter(|f| surviving_peek.as_ref().map(|s| s.fingerprint != **f).unwrap_or(true)).collect();
        match candidates.as_slice() {
            [one] => {
                let ok = person.yes_no(Public(Question { text: format!("the LOST anchor is {} — the default, the other enrolled anchor beside the surviving file; is that right?", row_text(one, &reads.records)) })).map_err(|_| abandoned())?;
                if !ok {
                    return Err(Halt::face("the lost anchor was not confirmed", "name it with `--lost <fp-prefix>`", "re-run"));
                }
                **one
            }
            _ => {
                let answer = person.ask(Public(Question { text: format!("which anchor was LOST? answer by fingerprint prefix:\n  {}\n> ", anchors.iter().map(|f| row_text(f, &reads.records)).collect::<Vec<_>>().join("\n  ")) })).map_err(|_| abandoned())?;
                let prefix = answer.trim().to_ascii_lowercase();
                let m: Vec<&Fingerprint> = anchors.iter().filter(|f| f.to_hex().starts_with(&prefix) && !prefix.is_empty()).collect();
                match m.as_slice() {
                    [one] => **one,
                    _ => return Err(Halt::face(format!("`{prefix}` names no single anchor"), "pick by a prefix of at least one R42 group", "re-run with `--lost <fp-prefix>`")),
                }
            }
        }
    };
    let lost_label = reads.records.label_of(&lost_fp);
    let surviving_fp_expected: Option<Fingerprint> = anchors.iter().find(|f| **f != lost_fp).copied();
    let surviving_label = surviving_peek.as_ref().and_then(|s| s.label.clone()).or_else(|| surviving_fp_expected.and_then(|f| reads.records.label_of(&f)));
    // THE FINDER QUESTION (P27).
    let finder = person.yes_no(Public(Question { text: format!("could the lost sheet ({}) be in someone else's hands — found, taken, or simply not known destroyed? (the race arm re-reads the set after each write and retires every key you do not account for)", row_text(&lost_fp, &reads.records)) })).map_err(|_| abandoned())?;
    let accounted_at_l0: Vec<Fingerprint> = reads.walk.set.enrolled.iter().map(|e| e.fingerprint).collect();
    let race = finder;
    // L1: the two boxes, PREFILLED from the LOST paper's label.
    let boxes = |person: &mut dyn Person, attempt: usize| -> Result<Vec<Label>, Halt> {
        let token = crate::hex::encode(&crate::sign::fresh_bytes(2));
        let mut labels = Vec::new();
        for which in ["a", "b"] {
            let default = format!("{}-{token}-{which}", lost_label.as_deref().unwrap_or("anchor"));
            let label = loop {
                let text = person
                    .label(Public(LabelBox {
                        title: format!("name fresh anchor {which}{}", if attempt > 0 { format!(" (re-run {attempt}, a fresh pair)") } else { String::new() }),
                        statements: vec![
                            "two distinct permanent names, distinct from EACH OTHER and from the LOST paper's own — this names the SHEET and never where you keep it (AUTH-5.42)".into(),
                            format!("prefilled from the LOST paper's label (`{}`); the surviving file's label is `{}` — avoid it", lost_label.as_deref().map(render_inert).unwrap_or_else(|| "none".into()), surviving_label.as_deref().map(render_inert).unwrap_or_else(|| "none".into())),
                            "public forever and uncorrectable: fixing a typo costs a keypair".into(),
                        ],
                        default: Some(default.clone()),
                    }))
                    .map_err(|_| abandoned())?;
                match Label::new(&text) {
                    Ok(l) => break l,
                    Err(fault) => say(person, "AUTH-1.24", format!("that name is refused at the box: {fault}; name the sheet again")),
                }
            };
            labels.push(label);
        }
        Ok(labels)
    };
    let mut labels = boxes(person, 0)?;
    // L2: R1 with the SURVIVING artifact, then R2.
    let whose = whose_account(person, &account, opts.principal)?;
    let cx = ImportContext { board, store, account: &account, principal: opts.principal, set_account: &reads.walk.set_account, set: &reads.walk.set, records: &reads.records, own: &own, anchor_path: opts.anchor.as_deref(), whose, cell: &reads.cell };
    let surviving: ImportedAnchor = match import_anchor(person, &cx)? {
        ImportOutcome::Anchor(a) => *a,
        ImportOutcome::Neither => return Err(no_artifact_face(person, &cx)),
    };
    if surviving.fingerprint == lost_fp {
        return Err(Halt::face("the artifact handed in is the LOST paper's own key", "this arm runs under the SURVIVING paper's session; the lost one holds no session any party but its finder could open", "hand in the surviving paper, or name the lost one with `--lost`"));
    }
    if whose == Whose::Agent {
        return Err(Halt::face("the loss arm at an agent's account is the owner's custody rotation", "AUTH-5.62: the custody pair is the owner's; this arm enrolls a fresh pair for a PERSON's own account", "run the walk at your own account; the agent's custody rotation lands with the attendant campaign"));
    }
    let session = handshake(board, Scope::Full, &surviving.signer, opts.principal, Site::Recover)?;
    let facts = Facts { account: account.clone(), principal: opts.principal, origin: board.dialed().clone() };
    let mut retired: Vec<Fingerprint> = Vec::new();
    let mut enrolled_pair: Vec<Fingerprint> = Vec::new();
    let result = (|| -> Result<(String, Vec<AnchorArtifact>), Halt> {
        let fs_reads = FirstSessionReads::take(board, &account, &surviving.fingerprint, Some(store))?;
        let mut new_link: Option<String> = None;
        let mut artifacts: Vec<AnchorArtifact> = Vec::new();
        for attempt in 0..3 {
            // L3: AUTH-5.54 steps 1–3 CITED — statement (b) alone, then the
            // pair exported and DROPPED; the boxes are L1's, the re-import L5's.
            two_places(person, opts.paper);
            let export = BackupOptions { labels: Vec::new(), destinations: opts.anchor_out.clone(), paper: opts.paper, store: Some(store.root().to_path_buf()), host_name: opts.host_name.clone(), date: opts.date.clone() };
            let backup = export_pair(person, &export, &labels, Some(&facts))?;
            // L4: `first_session` FIRST; then BOTH fresh anchors as ONE record.
            first_session(board, &fs_reads, &session, &surviving.signer, Some(store))?;
            let entries: Vec<Enrollment> = backup.anchors.iter().map(|a| Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).expect("a label the box admitted")).collect();
            let id = format!("recover.loss.enroll.{}", &backup.anchors[0].fingerprint.to_hex()[..8]);
            let link = match deposit(board, session.token(), &Deposit { home: &fs_reads.home, subject: &account, kind: DepositKind::Enroll(entries), hand: Some(&surviving.signer), id: &id })? {
                DepositOutcome::Deposited { link, .. } => link,
                DepositOutcome::Committed { .. } => {
                    let records = credential_records(board, &account, &own)?;
                    records.enrollment_of(&backup.anchors[0].fingerprint).map(|r| r.link.clone()).ok_or_else(|| Halt::face("the fresh pair's enroll link was not found", "the read after a reconciled enrollment names none", "re-run"))?
                }
            };
            say(person, "AUTH-5.59 step 1", format!("BOTH fresh anchors enrolled as ONE anchor-flagged record under the surviving paper's session: {} and {}", backup.anchors[0].fingerprint, backup.anchors[1].fingerprint));
            enrolled_pair = backup.anchors.iter().map(|a| a.fingerprint).collect();
            // L5: step 3 for EACH new anchor — the re-import, the probe, the wipe.
            let mut failed: Option<usize> = None;
            for (i, artifact) in backup.anchors.iter().enumerate() {
                match reimport_anchor(person, artifact, opts.paper, i)? {
                    Some(fresh) => {
                        let probe = handshake(board, Scope::Content, &fresh, opts.principal, Site::Recover)?;
                        let _ = probe.close();
                        drop(fresh);
                        say(person, "AUTH-5.59 step 3", format!("anchor {} ({}): re-imported from its artifact, fingerprint first, verified locally, a probe session opened and closed, its token presented nowhere; the seed wiped", artifact.fingerprint, artifact.label));
                    }
                    None => {
                        failed = Some(i);
                        break;
                    }
                }
            }
            if let Some(i) = failed {
                // THE FAILURE ARM: retire the just-enrolled fingerprint from
                // this session, then re-run from step 1 under a fresh pair.
                say(person, "AUTH-5.59 step 3", format!("anchor {} ({}) did not re-import from its artifact: an ENROLLED anchor whose private half exists nowhere — it is retired from the session this gesture holds, and the walk re-runs from step 1 under a fresh pair (attempt {})", backup.anchors[i].fingerprint, backup.anchors[i].label, attempt + 2));
                let set = reread(board, &account)?;
                let records = credential_records(board, &account, &own)?;
                for a in &backup.anchors {
                    retire_one(board, person, &session, &surviving.signer, &reads, &set, &records, &a.fingerprint, &held, PreviewSite::LossArm)?;
                    retired.push(a.fingerprint);
                }
                for a in &backup.anchors {
                    if let Some(p) = &a.file {
                        let _ = std::fs::remove_file(p);
                    }
                }
                labels = boxes(person, attempt + 1)?;
                continue;
            }
            new_link = Some(link);
            artifacts = backup.anchors;
            break;
        }
        let Some(new_link) = new_link else {
            return Err(Halt::face("three fresh pairs in a row failed their re-import", "the artifacts' media does not read back", "check the destination media and re-run"));
        };
        // THE TRAIL between L5 and L6: from the LOST anchor's enroll link to
        // the new pair's, signed by the surviving anchor.
        let old_link = reads.records.enrollment_of(&lost_fp).map(|r| r.link.clone()).ok_or_else(|| Halt::face("the lost anchor's enroll link was not found", "the trail's `old` is the address the admitted read returns", "re-run"))?;
        let supersession = Trail { home: &fs_reads.home, old: &old_link, new: &new_link };
        let trail = match supersession.present(board)? {
            Some(claim) => {
                say(person, "AUTH-5.59 step 3", format!("the trail already stands at {claim}: resumed by reading"));
                claim
            }
            None => {
                let claim = supersession.write(board, &session, &surviving.signer, "recover.loss.trail")?;
                say(person, "AUTH-5.59 step 2", format!("the supersession trail is written at {claim}: from the lost anchor's enroll link {old_link} to the new pair's {new_link}, attested by the surviving anchor"));
                claim
            }
        };
        // L6: the LOST anchor retired; on the race arm every unaccounted key.
        let mut set = reread(board, &account)?;
        let mut records = credential_records(board, &account, &own)?;
        if set.enrolled(&lost_fp).is_some() {
            retire_one(board, person, &session, &surviving.signer, &reads, &set, &records, &lost_fp, &held, PreviewSite::LossArm)?;
            retired.push(lost_fp);
            set = reread(board, &account)?;
        } else {
            say(person, "AUTH-5.17", format!("the lost anchor {lost_fp} already stands retired"));
        }
        if race {
            for round in 0..8 {
                let unaccounted: Vec<Fingerprint> = set.enrolled.iter().filter(|e| !accounted_at_l0.contains(&e.fingerprint) && !enrolled_pair.contains(&e.fingerprint) && !retired.contains(&e.fingerprint)).map(|e| e.fingerprint).collect();
                if unaccounted.is_empty() {
                    break;
                }
                records = credential_records(board, &account, &own)?;
                say(person, "AUTH-5.64", format!("race round {}: {} fingerprint(s) enrolled since L0 — a finder's device key as much as an anchor", round + 1, unaccounted.len()));
                for fp in unaccounted {
                    retire_one(board, person, &session, &surviving.signer, &reads, &set, &records, &fp, &held, PreviewSite::LossArm)?;
                    retired.push(fp);
                    set = reread(board, &account)?;
                }
            }
            say(person, "AUTH-5.64 (residual)", "COMPLETION is the read after the last write; a finder writing at machine rate can survive the rounds — TERMINATION IS NOT GUARANTEED; the recovery read over this account (AUTH-5.89) and, at a served board, the report (AUTH-5.60 step 4) exist beside it");
        }
        Ok((trail, artifacts))
    })();
    // L7: the close; the end face.
    let _ = session.close();
    surviving.dispose(person);
    let (trail, artifacts) = result?;
    let noun = if opts.paper { "sheets" } else { "anchor files" };
    say(
        person,
        "AUTH-5.59 step 5",
        format!(
            "THE END: THREE anchors stand enrolled — the surviving old paper and the fresh pair ({}) — the trail at {trail}. Keep the fresh {noun} apart from each other (statement (b)) and the OLD sheet apart from both, as senior as they are and still outranking every device session (AUTH-5.47), or destroy it — never discard it where it can be found. The LOST sheet, retired, opens nothing, ever, if it turns up (AUTH-2.98): destroy it so it is not filed beside the sheets that replaced it. NO COMMAND IN THIS VERSION RETIRES THE SURVIVING OLD PAPER — that is the anchor REPLACEMENT run under its own session, LATER. No `closed` arrives and nothing waits for one.",
            artifacts.iter().map(|a| format!("{} ({})", a.fingerprint, a.label)).collect::<Vec<_>>().join(", ")
        ),
    );
    Ok(Recovered { facts, enrolled: artifacts.iter().map(|a| a.fingerprint).collect(), retired, binding_line: None, containment: false, recovery_read: Vec::new(), warnings: Vec::new() })
}
