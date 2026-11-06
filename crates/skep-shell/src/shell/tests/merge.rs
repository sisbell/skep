//! The merge family (`client.md` §4b.1's merge row; THE MERGE BRIDGE LANE).
//!
//! The suite checks the rules the shell alone keeps, with no daemon behind
//! it — the rows' own members read before the session, `land` and `undo`
//! with nothing composed `no_merge`, a bare session refused — and, against
//! the real daemon, the family end to end: a daughter composed and landed
//! into a fresh draft staged from the head and into a named one, each by
//! one write; the undo and the withdrawal each one write, the undo refused
//! `arrangement_moved` where the draft moved since, nothing wiped; the
//! re-open landing nothing, reading the side at the marker's position and
//! settling a gap the draft no longer arranges; `resolutions` refused where
//! they name no gap or no choice the gap admits, nothing landed; the
//! landing on the trunk through the publication family's shot with the
//! claim, then the record; the draft side composed and landed with no
//! claim, its re-open reading the side as merged; the merged arm naming the
//! member and writing a missing record once; the `head_moved` race typed,
//! nothing re-sent; and the composition dying with its session.

use super::publication::{ground, register, second_device, signed_facts, Ground};
use super::*;
use crate::sessions::Facts;

/// The ground every daemon cell stands on: E published as E.1 ("the fox")
/// from D, D on to E.2 ("the fox jumps"), and S — staged from E.1 and so
/// behind — published as the daughter E.1.1 ("the fox today"): the merge
/// of E.2 with E.1.1 over base E.1 has both sides adding at one spot, an
/// `order` gap.
struct Family {
    edition: String,
    e1: String,
    e2: String,
    e11: String,
}

fn family(g: &Ground) -> Family {
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let open = |draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let confirm = || g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let d = g.staged(&edition, "the fox");
    open(&d);
    let e1 = format!("{edition}.1");
    let first = confirm();
    assert_eq!(first["member"].as_str(), Some(e1.as_str()), "{first}");
    let s = g.addr(skep_client::board::frames::stage(&e1, None));
    g.op(json!({"op": "insert", "doc": s, "at": {"subspace": "1", "ordinal": "8"}, "values": [" today"], "as_of": g.position()}));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "8"}, "values": [" jumps"], "as_of": g.position()}));
    open(&d);
    let e2 = format!("{edition}.2");
    let second = confirm();
    assert_eq!(second["member"].as_str(), Some(e2.as_str()), "{second}");
    open(&s);
    let e11 = format!("{e1}.1");
    let daughter = confirm();
    assert_eq!(daughter["member"].as_str(), Some(e11.as_str()), "the daughter under E.1: {daughter}");
    Family { edition, e1, e2, e11 }
}

/// Holds a report to its declaration, every member of it.
fn assert_report_declared(report: &Value) {
    crate::shapes::assert_declared("MergeReport", report);
    for side in report["sides"].as_array().unwrap() {
        crate::shapes::assert_declared("MergeSide", side);
    }
    for run in report["runs"].as_array().unwrap() {
        crate::shapes::assert_declared("MergeRun", run);
    }
    for gap in report["gaps"].as_array().unwrap() {
        crate::shapes::assert_declared("MergeGap", gap);
        for run in gap["runs"].as_array().unwrap() {
            crate::shapes::assert_declared("GapRun", run);
        }
    }
    crate::shapes::assert_declared("RunCounts", &report["counts"]);
}

/// The `set_arrangement` rows under `doc` since `since`, each as
/// `(base present, merge present)`.
fn arrangement_rows(g: &Ground, doc: &str, since: u64) -> Vec<(bool, bool)> {
    let entry = g.shell.sessions.get(&g.session).unwrap();
    changes_under(&entry.board, &entry.token, doc, since).iter().filter(|r| r["op"] == "set_arrangement").map(|r| (r["base"].is_string(), r["merge"].is_object())).collect()
}

/// Checks the rows' own members and the family's answers with nothing
/// composed, with no daemon behind the shell.
///
/// `merge.compose` reads its members before the session — `doc` missing or
/// no bare document, `alternative` no daughter of `doc`'s chain, both forms
/// or neither, `into` the draft side itself — each `malformed_args` naming
/// the member; in their form the call goes on to the session, which is
/// gone. `merge.withdraw` reads `draft` first. `land` and `undo` with
/// nothing composed answer `no_merge` naming the session, and a bare
/// session is refused `write_in_bare_session` naming the call at each row
/// (the mutants that look the session up first, or read a member as
/// absent, answer `session_ended` or dial).
#[test]
fn the_rows_read_their_members_first_and_answer_no_merge_with_nothing_composed() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let signed = register(&shell, "8e", signed_facts(2));
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let what = |args: Value| {
        let refused = shell.call("merge.compose", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": "s-gone", "alternative": "1.0.2.0.1.1.1"})), "doc", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1.1", "alternative": "1.0.2.0.1.1.1"})), "doc", "a member, no bare document");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1"})), "alternative", "a trunk member is no daughter");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.3.0.1.1.1"})), "alternative", "another document's daughter");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1", "draft": "1.0.2.0.4"})), "draft", "both forms");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1"})), "alternative or draft", "neither form");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "draft": "1.0.2.0.4", "into": "1.0.2.0.4"})), "into", "the draft side itself");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1", "into": 7})), "into", "another form");
    for in_form in [json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1"}), json!({"session": "s-gone", "doc": "1.0.2.0.1", "draft": "1.0.2.0.4", "into": "1.0.2.0.5"})] {
        assert_eq!(shell.call("merge.compose", &in_form).unwrap_err().name(), "session_ended", "{in_form}: in its form, the members pass to the session");
    }
    let refused = shell.call("merge.withdraw", &json!({"session": "s-gone"})).unwrap_err().to_value();
    assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("draft")));
    for call in ["merge.land", "merge.undo"] {
        let refused = shell.call(call, &json!({"session": signed})).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["session"].as_str()), ("no_merge", Some(signed.as_str())), "{call}: {v}");
        assert_eq!(shell.call(call, &json!({"session": bare})).unwrap_err().name(), "no_merge", "{call}: nothing composed is answered before the hand is asked");
    }
    let keyless = shell.call("merge.compose", &json!({"session": bare, "doc": "1.0.1.0.1", "alternative": "1.0.1.0.1.1.1"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("merge.compose")), "{keyless}");
    let keyless = shell.call("merge.withdraw", &json!({"session": bare, "draft": "1.0.1.0.4"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("merge.withdraw")), "{keyless}");
}

/// Checks a daughter composed and landed, and taken back, against the
/// daemon.
///
/// With no `into`, `merge.compose` lands M in a FRESH draft staged from the
/// head — `fresh` true, the draft's recorded base E.2 and its marker naming
/// E.1.1 under E.2 at the landing's position, its text the merge of both
/// sides, the report declared with its one unsettled `order` gap; the
/// composition stands and `merge.undo` takes the landing back by ONE
/// `set_arrangement` — the draft's text E.2's again, its base restored with
/// its extent, its marker gone, one arrangement row under the draft naming
/// a base and no merge — and the composition is gone. With `into` a level
/// draft L staged from E.2, the landing goes into L, `fresh` false. A burst
/// to L after the landing makes `merge.undo` the board's `arrangement_moved`
/// — its `site.as_of` the landing's position — nothing wiped, the
/// composition standing; `merge.withdraw` then takes the merge out of L by
/// ONE `set_arrangement`, its words kept, its marker gone, the landing's
/// record replaced, and the composition gone (the mutants that land by a
/// second write, stage where a draft is named, drop the marker, or keep a
/// taken-back composition standing).
#[test]
fn the_family_lands_a_daughter_into_a_fresh_draft_and_into_a_named_one_and_takes_each_back_by_one_write() {
    use skep_client::board::frames::doc_metadata;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    // A fresh draft: staged from the head first, then the one write.
    let before = g.position();
    let report = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&report);
    assert_eq!((report["outcome"].as_str(), report["form"].as_str(), report["fresh"].as_bool(), report["head_moved"].is_null()), (Some("landed"), Some("daughter"), Some(true), true), "{report}");
    assert_eq!((report["doc"].as_str(), report["head"].as_str(), report["base"].as_str(), report["side"].as_str()), (Some(f.edition.as_str()), Some(f.e2.as_str()), Some(f.e1.as_str()), Some(f.e11.as_str())), "{report}");
    let fresh = report["into"].as_str().expect("the fresh draft").to_string();
    let position = report["position"].as_u64().expect("the landing's position");
    assert!(position > before, "{report}");
    assert!(report["record_link"].is_string() && !report["over_cap"].as_bool().unwrap(), "{report}");
    let gaps = report["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1, "both sides added at one spot: {report}");
    assert_eq!((gaps[0]["kind"].as_str(), gaps[0]["settled"].as_bool(), gaps[0]["resolved_by"].is_null()), (Some("order"), Some(false), true), "{report}");
    let meta = g.op(doc_metadata(&fresh));
    assert_eq!((meta["base"].as_str(), meta["merge"]["sides"].clone(), meta["merge"]["head"].as_str(), meta["merge"]["at"].as_u64()), (Some(f.e2.as_str()), json!([f.e11]), Some(f.e2.as_str()), Some(position)), "staged from the head, marked: {meta}");
    let text = g.text(&fresh, 19);
    assert!(text.starts_with("the fox") && text.contains(" jumps") && text.contains(" today") && text.len() == 19, "{text:?}");
    // The undo: one write, the draft as it stood.
    let since = g.position();
    let undone = g.call("merge.undo", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Undone", &undone);
    assert_eq!((undone["draft"].as_str(), undone["restored"].clone(), undone["record"].is_string()), (Some(fresh.as_str()), json!({"base": f.e2, "extent": 13}), true), "{undone}");
    assert_eq!(g.text(&fresh, 13), "the fox jumps");
    assert!(g.op(doc_metadata(&fresh))["merge"].is_null(), "the marker gone");
    assert_eq!(arrangement_rows(&g, &fresh, since), [(true, false)], "one arrangement row, a base and no merge");
    assert_eq!(g.call("merge.undo", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the undo");
    // A named level draft: landed into, nothing staged.
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let report = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((report["outcome"].as_str(), report["into"].as_str(), report["fresh"].as_bool()), (Some("landed"), Some(l.as_str()), Some(false)), "{report}");
    let landed_at = report["position"].as_u64().unwrap();
    assert_eq!(g.op(doc_metadata(&l))["merge"]["sides"], json!([f.e11]));
    // A burst after the landing: the undo refused, nothing wiped.
    g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "20"}, "values": ["!"], "as_of": g.position()}));
    let moved = g.call("merge.undo", json!({"session": g.session})).unwrap_err();
    let v = moved.to_value();
    assert_eq!((moved.name(), v["kind"].as_str(), v["site"]["as_of"].as_u64()), ("arrangement_moved", Some("refused"), Some(landed_at)), "{v}");
    assert!(v["site"]["current"].is_u64(), "{v}");
    assert_eq!(g.text(&l, 20).len(), 20, "nothing wiped");
    // The withdrawal: one write, the words kept, the marker gone.
    let since = g.position();
    let withdrawn = g.call("merge.withdraw", json!({"session": g.session, "draft": l})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Withdrawn", &withdrawn);
    assert_eq!((withdrawn["draft"].as_str(), withdrawn["record"].is_string()), (Some(l.as_str()), true), "{withdrawn}");
    assert_eq!(g.text(&l, 20).len(), 20, "the words kept");
    assert!(g.op(doc_metadata(&l))["merge"].is_null(), "the marker gone");
    assert_eq!(arrangement_rows(&g, &l, since), [(true, false)], "one arrangement row");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the withdrawal");
    assert_eq!(g.call("merge.withdraw", json!({"session": g.session, "draft": l})).unwrap_err().name(), "no_merge", "no merge to take out");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the re-open, the resolutions and the landing on the trunk against
/// the daemon.
///
/// L takes the merge of E.2 with E.1.1; `merge.compose` again on the same
/// daughter into L is THE RE-OPEN: the report with nothing landed, its
/// `position` the marker's, the board's position unmoved, the gap unsettled
/// as it was; the draft's additions deleted whole, the re-open reads the
/// gap off the draft as SETTLED by the person. `merge.land` with a
/// resolution naming no gap, a choice no gap admits, a side not of the gap
/// or an anchor the gap does not name is refused `malformed_args` naming
/// `resolutions`, nothing landed; with a checked one it lands: the shot
/// through the publication family carrying the claim, E.3 acknowledged with
/// `supersede [E.1.1]`, the record written — read back by the next
/// `merge.compose` of the daughter, THE MERGED ARM, naming the member and
/// the standing record, whose gap the person resolved `omitted`, nothing
/// landed and nothing written again (the mutants that land at the re-open,
/// read the gap off the composition alone, apply an unchecked resolution,
/// or write the record twice).
#[test]
fn the_re_open_lands_nothing_and_a_checked_resolution_lands_on_the_trunk_with_the_claim_and_its_record() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let compose = || g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landed = compose();
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let position = landed["position"].as_u64().unwrap();
    let gap = landed["gaps"][0]["id"].as_u64().expect("the order gap");
    // The re-open: nothing landed.
    let before = g.position();
    let reopened = compose();
    assert_report_declared(&reopened);
    assert_eq!((reopened["outcome"].as_str(), reopened["into"].as_str(), reopened["position"].as_u64(), reopened["gaps"][0]["settled"].as_bool()), (Some("reopened"), Some(l.as_str()), Some(position), Some(false)), "{reopened}");
    assert_eq!(reopened["runs"], landed["runs"], "the side as compose read it");
    assert_eq!(g.position(), before, "nothing landed");
    // The gap's default no longer arranged: both additions deleted whole.
    g.op(json!({"op": "delete", "doc": l, "p": {"subspace": "1", "ordinal": "8"}, "width": "12", "as_of": g.position()}));
    assert_eq!(g.text(&l, 7), "the fox");
    let settled = compose();
    assert_eq!((settled["outcome"].as_str(), settled["gaps"][0]["settled"].as_bool(), settled["gaps"][0]["resolved_by"].as_str()), (Some("reopened"), Some(true), Some("person")), "{settled}");
    // The resolutions, UNTRUSTED.
    let before = g.position();
    for bad in [json!({"99": "omit"}), json!({gap.to_string(): "frob"}), json!({gap.to_string(): {"order": [7]}}), json!({gap.to_string(): {"keep_only": 9}}), json!({gap.to_string(): {"after": "1.0.9.0.1.0.1.1"}}), json!({gap.to_string(): {"order": []}}), json!({gap.to_string(): {"order": [0, 0]}})] {
        let refused = g.call("merge.land", json!({"session": g.session, "resolutions": bad})).unwrap_err().to_value();
        assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("resolutions")), "{bad}: {refused}");
    }
    assert_eq!(g.position(), before, "nothing landed");
    // A checked one: the landing on the trunk with the claim and the record.
    let landed = g.call("merge.land", json!({"session": g.session, "resolutions": {gap.to_string(): "omit"}})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("MergeLanded", &landed);
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone(), landed["daughter"].as_bool(), landed["claim"].as_bool()), (Some("landed"), Some(e3.as_str()), json!([f.e11]), Some(false), Some(false)), "{landed}");
    assert!(landed["record"].is_string() && landed["claims"].as_array().is_some_and(|c| c.len() == 1), "the record and the claim read back: {landed}");
    assert_eq!(g.text(&e3, 7), "the fox");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the landing");
    // THE MERGED ARM: the member named, the standing record, nothing written.
    let before = g.position();
    let merged = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&merged);
    assert_eq!((merged["outcome"].as_str(), merged["member"].as_str(), merged["record_link"].as_str(), merged.get("into")), (Some("merged"), Some(e3.as_str()), landed["record"].as_str(), None), "{merged}");
    assert_eq!(merged["claims"], landed["claims"]);
    let record_gap = merged["record"]["gaps"].as_array().unwrap().iter().find(|gp| gp["id"].as_u64() == Some(gap)).expect("the gap in the record");
    assert_eq!((record_gap["resolved_by"].as_str(), record_gap["placed"].as_str()), (Some("person"), Some("omitted")), "the person's resolution in the record: {merged}");
    assert_eq!(g.position(), before, "nothing landed, nothing written");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "a merged daughter composes nothing to land");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the draft side against the daemon.
///
/// B, staged from E.1 and behind the head E.2 with words of its own,
/// composes as the merge's side into L, a level draft: landed, L's marker
/// naming B — a private draft — and the report's draft side carrying the
/// position it was read at; L's `publication.open` carries no claim. B
/// written since, the re-open reads the side AS COMPOSE READ IT — the
/// draft side's position the marker's, the runs the first report's, B's
/// new words nowhere in them — and lands nothing. `merge.land` opens the
/// panel itself, B named `also`, and lands E.3 holding both sides' words
/// with NO claim, `supersede []` (the mutants that claim a private draft,
/// read a moved side as it stands, or drop `also` and window B's words).
#[test]
fn the_draft_side_composes_and_lands_with_no_claim_and_its_re_open_reads_the_side_as_merged() {
    use skep_client::board::frames::doc_metadata;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let b = g.addr(skep_client::board::frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let compose = || g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landed = compose();
    assert_report_declared(&landed);
    assert_eq!((landed["outcome"].as_str(), landed["form"].as_str(), landed["side"].as_str(), landed["into"].as_str()), (Some("landed"), Some("draft"), Some(b.as_str()), Some(l.as_str())), "{landed}");
    assert_eq!((landed["sides"][1]["at"].as_str(), landed["sides"][1]["role"].as_str(), landed["sides"][1]["position"].as_u64()), (Some(b.as_str()), Some("draft"), Some(landed["as_of"].as_u64().unwrap())), "{landed}");
    let marker = g.op(doc_metadata(&l))["merge"].clone();
    assert_eq!((marker["sides"].clone(), marker["head"].as_str()), (json!([b]), Some(f.e2.as_str())), "{marker}");
    let text = g.text(&l, 21);
    assert!(text.contains(" jumps") && text.contains(" quietly") && text.len() == 21, "{text:?}");
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l, b], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["count"]["supersede"], json!([]), "a draft-side marker carries no claim: {panel}");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    // B moves; the re-open reads it as merged.
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "16"}, "values": [" again"], "as_of": g.position()}));
    let before = g.position();
    let reopened = compose();
    assert_eq!((reopened["outcome"].as_str(), reopened["sides"][1]["position"].as_u64(), reopened["position"].as_u64()), (Some("reopened"), marker["at"].as_u64(), marker["at"].as_u64()), "the side at the marker's position: {reopened}");
    assert_eq!(reopened["runs"], landed["runs"], "the side as compose read it, B's new words nowhere");
    assert_eq!(g.position(), before, "nothing landed");
    // The landing on the trunk: no claim.
    let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("MergeLanded", &landed);
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["member"].as_str(), landed["supersede"].clone(), landed["daughter"].as_bool()), (Some(e3.as_str()), json!([]), Some(false)), "{landed}");
    assert!(landed["record"].is_string(), "{landed}");
    let text = g.text(&e3, 21);
    assert!(text.contains(" jumps") && text.contains(" quietly") && text.len() == 21, "both sides' words, B's as the document's own: {text:?}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the merged arm's record written once where the page's own slot
/// published the merge, against the daemon.
///
/// L takes the merge of E.2 with E.1.1 (the landing's record names L);
/// the page takes the publish slot itself — `publication.open` carrying the
/// claim, `confirm` acknowledged E.3 — which writes no merge record of the
/// member. `merge.compose` of the daughter then answers MERGED, naming E.3,
/// and WRITES the missing record — its link new, the board's position
/// moved by the record's two writes; a second `merge.compose` names the
/// same record, nothing written (the mutants that re-land a merged
/// daughter, skip the record, or write it again).
#[test]
fn merged_names_the_member_and_writes_a_missing_record_once() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landing_record = landed["record_link"].as_str().unwrap().to_string();
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["count"]["supersede"], json!([f.e11]), "{panel}");
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((acked["member"].as_str(), acked["supersede"].clone()), (Some(e3.as_str()), json!([f.e11])), "{acked}");
    let before = g.position();
    let merged = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&merged);
    assert_eq!((merged["outcome"].as_str(), merged["member"].as_str()), (Some("merged"), Some(e3.as_str())), "{merged}");
    let record = merged["record_link"].as_str().expect("the record written").to_string();
    assert_ne!(record, landing_record, "a record of the member's landing, not the draft's");
    assert!(g.position() > before, "the record's writes");
    assert_eq!(merged["claims"].as_array().map(Vec::len), Some(1), "{merged}");
    let after = g.position();
    let again = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((again["outcome"].as_str(), again["record_link"].as_str()), (Some("merged"), Some(record.as_str())), "{again}");
    assert_eq!((again["record"]["landed"]["member"].as_str(), g.position()), (Some(e3.as_str()), after), "the standing record, nothing written again: {again}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the `head_moved` race typed and the composition's death with its
/// session, against the daemon.
///
/// L takes the merge of E.2 with E.1.1 and the page opens L's panel, the
/// claim riding; a SECOND DEVICE's shell publishes E.3 meanwhile. The first
/// `merge.land` re-reads the base and re-states the standing `behind`,
/// nothing sent; the second sends the claim as the panel composed it at the
/// open, which the board refuses WHOLE, `supersede_refused` with `detail`
/// `head_moved` and `head` E.3, crossing as the board answered it — the
/// board's position unmoved, nothing re-sent, the composition gone, so a
/// third `merge.land` answers `no_merge`. A new merge composed on E.3 into
/// a fresh level draft then dies with its session: the session closed and
/// another opened, `merge.land` and `merge.undo` answer `no_merge` (the
/// mutants that drop the claim at a moved standing and land a daughter
/// silently, re-send after the refusal, or keep a dead session's
/// composition).
#[test]
fn the_head_moved_race_is_typed_nothing_re_sent_and_a_composition_dies_with_its_session() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((panel["count"]["supersede"].clone(), panel["standing"].as_str()), (json!([f.e11]), Some("at_head")), "{panel}");
    // The second device moves the head.
    let second = second_device(&dir, &sd);
    let t = second.addr(skep_client::board::frames::stage(&f.e2, None));
    second.op(json!({"op": "insert", "doc": t, "at": {"subspace": "1", "ordinal": "14"}, "values": ["!"], "as_of": second.position()}));
    second.call("publication.open", json!({"session": second.session, "draft": t, "doc": f.edition, "readable_drafts": [t], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!(second.call("publication.confirm", json!({"session": second.session})).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e3.as_str()));
    second.shell.shutdown();
    let before = g.position();
    let restated = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((restated["outcome"].as_str(), restated["standing"].as_str()), (Some("restated"), Some("behind")), "the standing moved, nothing sent: {restated}");
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationRefused", &refused);
    assert_eq!((refused["outcome"].as_str(), refused["arm"].as_str(), refused["detail"].as_str(), refused["head"].as_str()), (Some("refused"), Some("supersede_refused"), Some("head_moved"), Some(e3.as_str())), "{refused}");
    assert_eq!(g.position(), before, "refused whole, nothing re-sent");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the race: made again on the head the refusal names");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    // A composition dies with its session.
    let l2 = g.addr(skep_client::board::frames::stage(&e3, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l2})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), landed["head"].as_str()), (Some("landed"), Some(e3.as_str())), "composed on the new head: {landed}");
    g.call("close", json!({"session": g.session})).unwrap();
    let session = g.call("session", json!({"board": g.board})).unwrap()["session"].as_str().unwrap().to_string();
    for call in ["merge.land", "merge.undo"] {
        assert_eq!(g.call(call, json!({"session": session})).unwrap_err().name(), "no_merge", "{call}: the composition died with its session");
    }
    g.shell.shutdown();
    sd.shutdown();
}
