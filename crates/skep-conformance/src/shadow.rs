//! The golden-side shadow: per golden document, the byte sequence its
//! content subspace holds after each recorded edit, plus the symbolic names
//! bound to them ("source", "target", "doc1"…) and the CURRENT-DOCUMENT REGISTER
//! the recording scripts kept implicitly (ops without a `doc` field target
//! the most recently *named* document — named by a create/open/version
//! result, an explicit doc field, or an expectation's docid).
//!
//! The shadow exists ONLY to translate text-denoted references the goldens
//! use. Its content follows the RECORDED ops (plus the grounding pre-pass's
//! inferred setup) whatever skep answers, so a skep divergence cannot bend
//! a later translation; a created document, version or link enters it only
//! when skep made it too, so every name it resolves has an α-image. In the
//! play pass it changes only through `play`'s `Cx` world-change methods,
//! which state that rule.

use std::collections::BTreeMap;
use std::ops::Range;

/// The bytes `[ord, ord + width)` name in a `len`-byte text: 1-based,
/// clamped to the text and saturating at both ends, so no recorded ordinal
/// or width (`u64::MAX` included) panics a read or an edit of the mirror.
fn byte_range(len: usize, ord: u64, width: u64) -> Range<usize> {
    let fit = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
    let start = fit(ord.saturating_sub(1)).min(len);
    start..start.saturating_add(fit(width)).min(len)
}

/// Per-document shadow state, keyed by GOLDEN docid string.
#[derive(Clone, Debug, Default)]
struct DocShadow {
    /// Content-subspace bytes, ordinal i ↦ text[i-1].
    text: Vec<u8>,
    /// Link-subspace occupancy: how many links are seated here.
    link_count: u64,
}

/// One created link as the harness grounded it: golden id plus both endsets
/// as (golden doc, ordinal, width) triples — the world knowledge traversal
/// macros resolve hops from (round 4: hop resolution uses recorded endsets,
/// never text re-search).
#[derive(Clone, Debug)]
pub struct ShadowLink {
    pub golden: String,
    pub from: Vec<(String, u64, u64)>,
    pub to: Vec<(String, u64, u64)>,
}

/// One of the recording scripts' standing role names
/// ([`Shadow::resolve_doc`]): each names a document by convention, whether
/// or not a document answers to it yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// The `n`th document created, 0-based: "source"/"doc1"/A… the first,
    /// "target"/"doc2"/B… the second, "doc3"/C the third, "doc4"/D the
    /// fourth.
    Created(usize),
    /// "same doc"/"current"/"this"/"self": the current-document register.
    Register,
    /// "version"/"copy": the last version created.
    Version,
}

impl Role {
    fn of(r: &str) -> Option<Role> {
        Some(match r {
            "source" | "doc" | "doc1" | "original" | "first" | "home" | "A" | "a" => {
                Role::Created(0)
            }
            "target" | "doc2" | "second" | "dest" | "destination" | "B" | "b" => Role::Created(1),
            "doc3" | "third" | "C" | "c" => Role::Created(2),
            "doc4" | "fourth" | "D" | "d" => Role::Created(3),
            "same doc" | "current" | "this" | "self" => Role::Register,
            "version" | "copy" => Role::Version,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct Shadow {
    docs: BTreeMap<String, DocShadow>,
    /// Symbolic name → golden docid ("source" → "1.1.0.1.0.1").
    names: BTreeMap<String, String>,
    /// Every golden docid the shadow holds, once each, in creation order
    /// ([`Shadow::created`]) — the "doc1"/"first"/"second" fallbacks count in
    /// it.
    created: Vec<String>,
    /// The current-document register (see module docs).
    current: Option<String>,
    /// The last document a CONTENT write touched (insert/delete/pivot/swap,
    /// setup steps included) — the doc a "full_text_after"-style probe reads
    /// (round-5 item: the probe targets the document the setup's INSERT
    /// modified, not whatever the register drifted to).
    pub last_written: Option<String>,
    /// The golden id of the most recently created link.
    pub last_link: Option<String>,
    /// version source memo: version docid → source docid.
    pub version_of: BTreeMap<String, String>,
    /// "A->B"-style traversal edges: (from-name, to-name) → golden link id.
    pub arrow_links: BTreeMap<(String, String), String>,
    /// Every link created through the op surface, creation order, with the
    /// endsets it was grounded with (see [`ShadowLink`]).
    pub links: Vec<ShadowLink>,
    /// Root documents created (drives synthetic golden-id generation for
    /// `create_documents` ops that recorded no results).
    root_count: u64,
}

impl Shadow {
    pub fn new() -> Shadow {
        Shadow::default()
    }

    // ── creation & naming ──

    /// Mint document `golden`, empty, named `name` when one is given, and
    /// point the register at it. A document is minted once: the caller owes
    /// that the shadow does not hold `golden` yet ([`Shadow::knows`]), and a
    /// second mint is a harness bug, stopped here — it would list the
    /// document twice in creation order and advance the synthesized-id
    /// counter past the play pass's.
    pub fn create_doc(&mut self, golden: &str, name: Option<&str>) {
        assert!(
            !self.knows(golden),
            "a document is minted once: the shadow already holds {golden}"
        );
        self.docs.insert(golden.to_string(), DocShadow::default());
        self.created.push(golden.to_string());
        self.root_count += 1;
        if let Some(n) = name {
            self.bind_name(n, golden);
        }
        self.current = Some(golden.to_string());
    }

    /// Synthetic golden id for a create that recorded none: the next root
    /// ordinal under udanax's default account ("1.1.0.1.0.<n>"), matching
    /// the numbering later recorded creates in the same scenario continue
    /// (links/search_multiple_links_selective_removal: 3 unrecorded creates,
    /// then a recorded "1.1.0.1.0.4").
    pub fn synthesize_docid(&self) -> String {
        format!("1.1.0.1.0.{}", self.root_count + 1)
    }

    /// Bind symbolic `name` to golden `golden`. The first binding of a name
    /// stands: a later one for the same name changes nothing.
    pub fn bind_name(&mut self, name: &str, golden: &str) {
        self.names.entry(name.to_string()).or_insert_with(|| golden.to_string());
    }

    /// The current-document register: the document it points at, else the
    /// last document created.
    pub fn current(&self) -> Option<String> {
        self.current.clone().or_else(|| self.created.last().cloned())
    }

    /// Point the register at document `golden` when the shadow holds it (any
    /// op that names a document calls this); for a document it does not
    /// hold, the register stays where it was.
    pub fn set_current(&mut self, golden: &str) {
        if self.docs.contains_key(golden) {
            self.current = Some(golden.to_string());
        }
    }

    /// Resolve a doc reference: a dotted address passes through (a link
    /// address never does); a symbolic name resolves to the document it is
    /// bound to, then via the recording scripts' standing role names
    /// ([`Shadow::is_role_name`]): "source"/"doc1"/"doc"/"original"/A →
    /// first created ("source" and "original" prefer a bound name containing
    /// the word), "target"/"doc2"/B → second ("target" and "dest" likewise),
    /// "doc3"/C → third, "doc4"/D → fourth, "version"/"copy" → the last
    /// version created (nothing before one is — a version skep refused to
    /// make leaves its references ungroundable, the class rulings 20 and 20a
    /// freeze), "same doc"/"current" → the register. Any other string of two
    /// or more characters resolves to the first bound name, in name order,
    /// that it contains or is contained in ([`Shadow::find_named_containing`]):
    /// "Bank account" resolves to a document named "B". A caller asking
    /// whether a string names a document at all, rather than a text to
    /// locate, therefore hears yes for prose that merely shares a bound
    /// name's letters. `None` when nothing fits — the caller records it.
    pub fn resolve_doc(&self, r: &str) -> Option<String> {
        if crate::tum::is_link_address(r) {
            return None; // a link id is never a document reference
        }
        if crate::tum::parse_dotted(r).is_some() {
            return Some(r.to_string());
        }
        if let Some(g) = self.names.get(r) {
            return Some(g.clone());
        }
        match Role::of(r) {
            // Role names prefer a BOUND name containing the role over the
            // positional convention: a scenario naming its fourth doc
            // "shared_target" means THAT doc by "target", not doc #2
            // (links/search_multiple_links_selective_removal).
            Some(Role::Created(i)) => {
                self.find_named_containing_role(r).or_else(|| self.created.get(i).cloned())
            }
            Some(Role::Register) => self.current(),
            Some(Role::Version) => {
                self.created.iter().rev().find(|d| self.version_of.contains_key(*d)).cloned()
            }
            // "sourceN"/"peripheralN" positional group names bound at group
            // creation; also substring name matches ("target" →
            // "shared_target") for `by`-clause tokens.
            None => self.find_named_containing(r),
        }
    }

    /// Is `r` one of the recording scripts' standing role names ("source",
    /// "doc2", "C", "version", "current"…) — a document reference whether
    /// or not a document answers to it yet ([`Shadow::resolve_doc`])? Prose
    /// is none: "empty doc" describes a document, and names none.
    pub fn is_role_name(r: &str) -> bool {
        Role::of(r).is_some()
    }

    /// Role-containment lookup for the standing role words only ("source",
    /// "target"): single letters and doc-N conventions stay positional.
    fn find_named_containing_role(&self, role: &str) -> Option<String> {
        if !matches!(role, "source" | "target" | "dest" | "destination" | "original") {
            return None;
        }
        self.names
            .iter()
            .find(|(n, _)| n.contains(role))
            .map(|(_, g)| g.clone())
    }

    /// A doc whose bound name equals, contains, or is contained in `t`.
    pub fn find_named_containing(&self, t: &str) -> Option<String> {
        if t.len() < 2 {
            return None;
        }
        if let Some(g) = self.names.get(t) {
            return Some(g.clone());
        }
        self.names
            .iter()
            .find(|(n, _)| n.contains(t) || t.contains(n.as_str()))
            .map(|(_, g)| g.clone())
    }

    /// Does the shadow hold document `golden`?
    pub fn knows(&self, golden: &str) -> bool {
        self.docs.contains_key(golden)
    }

    /// Every document the shadow holds, once each, in creation order.
    pub fn created(&self) -> &[String] {
        &self.created
    }

    pub fn text_len(&self, golden: &str) -> u64 {
        self.docs.get(golden).map(|d| d.text.len() as u64).unwrap_or(0)
    }

    pub fn text_string(&self, golden: &str) -> String {
        self.docs
            .get(golden)
            .map(|d| String::from_utf8_lossy(&d.text).into_owned())
            .unwrap_or_default()
    }

    pub fn link_count(&self, golden: &str) -> u64 {
        self.docs.get(golden).map(|d| d.link_count).unwrap_or(0)
    }

    /// Docs in creation order that hold content, excluding `excluded` — the
    /// "which doc did the script copy from" fallback.
    pub fn content_docs_except(&self, excluded: &str) -> Vec<String> {
        self.created
            .iter()
            .filter(|g| g.as_str() != excluded && self.text_len(g) > 0)
            .cloned()
            .collect()
    }

    /// Locate `needle` in a document's current content; 1-based ordinal of
    /// its first byte. When `doc` is `None`, search every document in
    /// creation order and return the first (doc, ordinal) hit.
    pub fn find_text(&self, doc: Option<&str>, needle: &str) -> Option<(String, u64)> {
        let hit = |g: &str| -> Option<(String, u64)> {
            let d = self.docs.get(g)?;
            let t = &d.text;
            let n = needle.as_bytes();
            if n.is_empty() || n.len() > t.len() {
                return None;
            }
            t.windows(n.len()).position(|w| w == n).map(|p| (g.to_string(), p as u64 + 1))
        };
        match doc {
            Some(g) => hit(g),
            None => self.created.iter().find_map(|g| hit(g)),
        }
    }

    /// The Nth (1-based) occurrence of `needle`, counted per document in
    /// creation order (hint pins one doc) — the occurrence-selector
    /// grounding for "bank (second)"-style descriptions.
    pub fn find_text_nth(&self, doc: Option<&str>, needle: &str, nth: u64) -> Option<(String, u64)> {
        let n = needle.as_bytes();
        if n.is_empty() || nth == 0 {
            return None;
        }
        let mut seen = 0u64;
        let docs: Vec<&String> = match doc {
            Some(d) => self.created.iter().filter(|g| g.as_str() == d).collect(),
            None => self.created.iter().collect(),
        };
        for g in docs {
            let Some(d) = self.docs.get(g.as_str()) else { continue };
            let t = &d.text;
            if n.len() > t.len() {
                continue;
            }
            for p in 0..=(t.len() - n.len()) {
                if &t[p..p + n.len()] == n {
                    seen += 1;
                    if seen == nth {
                        return Some((g.clone(), p as u64 + 1));
                    }
                }
            }
        }
        None
    }

    /// Case-insensitive locate in ONE doc, returning the matched width (a
    /// description says "after first" for content "First ").
    pub fn find_text_ignoring_case(&self, doc: &str, needle: &str) -> Option<(String, u64, u64)> {
        let d = self.docs.get(doc)?;
        let hay = String::from_utf8_lossy(&d.text).to_ascii_lowercase();
        let n = needle.to_ascii_lowercase();
        if n.is_empty() {
            return None;
        }
        hay.find(&n).map(|p| (doc.to_string(), p as u64 + 1, n.len() as u64))
    }

    // ── the edit mirror (pure sequence bookkeeping, matching the recorded
    //    udanax semantics: 1-based ordinals, half-open ranges, each clamped
    //    to the text by `byte_range`). An edit changes only a document the
    //    shadow holds: one it does not hold stays unheld, and the edit
    //    changes nothing. ──

    /// Insert `bytes` before content ordinal `ord` of `golden`.
    pub fn insert(&mut self, golden: &str, ord: u64, bytes: &[u8]) {
        if let Some(d) = self.docs.get_mut(golden) {
            let i = byte_range(d.text.len(), ord, 0).start;
            d.text.splice(i..i, bytes.iter().copied());
            self.last_written = Some(golden.to_string());
        }
    }

    pub fn delete(&mut self, golden: &str, ord: u64, width: u64) {
        if let Some(d) = self.docs.get_mut(golden) {
            let removed = byte_range(d.text.len(), ord, width);
            d.text.drain(removed);
            self.last_written = Some(golden.to_string());
        }
    }

    /// Bytes covered by [ord, ord+width) — for vcopy source capture.
    pub fn slice(&self, golden: &str, ord: u64, width: u64) -> Vec<u8> {
        match self.docs.get(golden) {
            Some(d) => d.text[byte_range(d.text.len(), ord, width)].to_vec(),
            None => Vec::new(),
        }
    }

    /// Pivot at cuts (a, b, c): regions [a,b) and [b,c) transpose.
    pub fn pivot(&mut self, golden: &str, a: u64, b: u64, c: u64) {
        if a == 0 || b == 0 || c == 0 {
            return;
        }
        if let Some(d) = self.docs.get_mut(golden) {
            let (a, b, c) = (a as usize - 1, b as usize - 1, c as usize - 1);
            if a <= b && b <= c && c <= d.text.len() {
                let mut out = Vec::with_capacity(d.text.len());
                out.extend_from_slice(&d.text[..a]);
                out.extend_from_slice(&d.text[b..c]);
                out.extend_from_slice(&d.text[a..b]);
                out.extend_from_slice(&d.text[c..]);
                d.text = out;
                self.last_written = Some(golden.to_string());
            }
        }
    }

    /// Swap at cuts (s1, e1, s2, e2): regions [s1,e1) and [s2,e2) exchange,
    /// the middle stays.
    pub fn swap(&mut self, golden: &str, s1: u64, e1: u64, s2: u64, e2: u64) {
        if s1 == 0 || e1 == 0 || s2 == 0 || e2 == 0 {
            return;
        }
        if let Some(d) = self.docs.get_mut(golden) {
            let (s1, e1, s2, e2) =
                (s1 as usize - 1, e1 as usize - 1, s2 as usize - 1, e2 as usize - 1);
            if s1 <= e1 && e1 <= s2 && s2 <= e2 && e2 <= d.text.len() {
                let mut out = Vec::with_capacity(d.text.len());
                out.extend_from_slice(&d.text[..s1]);
                out.extend_from_slice(&d.text[s2..e2]);
                out.extend_from_slice(&d.text[e1..s2]);
                out.extend_from_slice(&d.text[s1..e1]);
                out.extend_from_slice(&d.text[e2..]);
                d.text = out;
                self.last_written = Some(golden.to_string());
            }
        }
    }

    /// Version: the new doc mirrors the source's text AND link count —
    /// udanax's CREATENEWVERSION copies both subspaces. The Nth version
    /// created in a scenario binds the names `vN`/`versionN` (the recording
    /// scripts' role names — versions/multiple_versions_same_source refers
    /// to its two unbound version results as "v1"/"v2"); `version` always
    /// names the LATEST version. A version is a document minted once, as
    /// [`Shadow::create_doc`]'s are: the caller owes that the shadow does not
    /// hold `new_golden` yet.
    pub fn version(&mut self, src: &str, new_golden: &str) {
        assert!(
            !self.knows(new_golden),
            "a document is minted once: the shadow already holds {new_golden}"
        );
        let (text, link_count) = match self.docs.get(src) {
            Some(d) => (d.text.clone(), d.link_count),
            None => (Vec::new(), 0),
        };
        self.docs.insert(new_golden.to_string(), DocShadow { text, link_count });
        self.created.push(new_golden.to_string());
        self.version_of.insert(new_golden.to_string(), src.to_string());
        let n = self.version_of.len();
        self.bind_name(&format!("v{n}"), new_golden);
        self.bind_name(&format!("version{n}"), new_golden);
        self.names.insert("version".to_string(), new_golden.to_string());
        let src_owned = src.to_string();
        self.names.entry("original".to_string()).or_insert(src_owned);
        self.current = Some(new_golden.to_string());
    }

    /// Seat one more link in the link subspace of `home_golden`, when the
    /// shadow holds it; an unheld home stays unheld.
    pub fn seat_link(&mut self, home_golden: &str) {
        if let Some(d) = self.docs.get_mut(home_golden) {
            d.link_count += 1;
        }
    }

    /// Record a created link's grounded endsets (play pass and setup steps
    /// call this on MakeLink success) — the traversal macros' hop-resolution
    /// world knowledge.
    pub fn record_link(
        &mut self,
        golden: &str,
        from: Vec<(String, u64, u64)>,
        to: Vec<(String, u64, u64)>,
    ) {
        if self.links.iter().any(|l| l.golden == golden) {
            return; // create_links:repeat re-recording the same id
        }
        self.links.push(ShadowLink { golden: golden.to_string(), from, to });
    }

    /// Links whose FROM endset lives in `doc`, optionally narrowed to those
    /// whose TO endset lives in `to_doc` — creation order.
    pub fn links_from(&self, doc: &str, to_doc: Option<&str>) -> Vec<&ShadowLink> {
        self.links
            .iter()
            .filter(|l| l.from.iter().any(|(d, _, _)| d == doc))
            .filter(|l| match to_doc {
                Some(t) => l.to.iter().any(|(d, _, _)| d == t),
                None => true,
            })
            .collect()
    }

    /// Links whose TO endset lives in `doc` — creation order.
    pub fn links_to(&self, doc: &str) -> Vec<&ShadowLink> {
        self.links.iter().filter(|l| l.to.iter().any(|(d, _, _)| d == doc)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "1.1.0.1.0.1";
    const OTHER: &str = "1.1.0.1.0.2";

    fn two_docs() -> Shadow {
        let mut s = Shadow::new();
        s.create_doc(SOURCE, Some("source"));
        s.create_doc(OTHER, Some("other"));
        s
    }

    /// `version` — and `copy`, unbound — names the last version CREATED,
    /// `…2.10` after `…2.9` whatever their text order, and nothing before
    /// one exists: never the second document, so a version skep refused to
    /// make stays ungroundable (rulings 20, 20a).
    #[test]
    fn version_names_the_last_version_created_and_nothing_before_one() {
        let mut s = two_docs();
        assert_eq!(s.resolve_doc("version"), None, "no version is made yet");
        assert_eq!(s.resolve_doc("copy"), None);
        s.version(OTHER, "1.1.0.1.0.2.9");
        s.version(OTHER, "1.1.0.1.0.2.10");
        assert_eq!(s.resolve_doc("version").as_deref(), Some("1.1.0.1.0.2.10"));
        assert_eq!(s.resolve_doc("copy").as_deref(), Some("1.1.0.1.0.2.10"));
        assert_eq!(s.resolve_doc("v1").as_deref(), Some("1.1.0.1.0.2.9"));
        assert_eq!(s.resolve_doc("original").as_deref(), Some(OTHER), "the version's source");
    }

    /// A role word prefers a bound name containing it ("target" →
    /// `shared_target`), a doc-N word stays positional whatever names
    /// contain it, an address passes through, and a link address names no
    /// document. Role words are references; prose is none.
    #[test]
    fn a_role_word_prefers_a_bound_name_and_a_link_is_never_a_document() {
        let mut s = two_docs();
        s.create_doc("1.1.0.1.0.3", Some("doc2_notes"));
        s.create_doc("1.1.0.1.0.4", Some("shared_target"));
        assert_eq!(s.resolve_doc("target").as_deref(), Some("1.1.0.1.0.4"));
        assert_eq!(s.resolve_doc("doc2").as_deref(), Some(OTHER));
        assert_eq!(s.resolve_doc("1.1.0.1.0.9").as_deref(), Some("1.1.0.1.0.9"));
        assert_eq!(s.resolve_doc("1.1.0.1.0.1.0.2.1"), None);
        assert!(Shadow::is_role_name("version") && Shadow::is_role_name("C"));
        assert!(!Shadow::is_role_name("empty doc") && !Shadow::is_role_name("doc2_notes"));
    }

    /// The mirror clamps every recorded extreme to its text: a width or an
    /// ordinal at the top of the range reads, deletes and inserts within
    /// the text, never past it and never by panicking.
    #[test]
    fn the_mirror_clamps_every_recorded_extreme() {
        let mut s = Shadow::new();
        s.create_doc(SOURCE, None);
        s.insert(SOURCE, 1, b"ABC");
        assert_eq!(s.slice(SOURCE, 2, u64::MAX), b"BC");
        assert_eq!(s.slice(SOURCE, u64::MAX, 1), b"");
        s.delete(SOURCE, 2, u64::MAX);
        assert_eq!(s.text_string(SOURCE), "A");
        s.insert(SOURCE, u64::MAX, b"X");
        assert_eq!(s.text_string(SOURCE), "AX");
    }

    /// A document is minted once: a second mint of a document the shadow
    /// holds is a harness bug, stopped where it is made.
    #[test]
    #[should_panic(expected = "a document is minted once: the shadow already holds 1.1.0.1.0.2")]
    fn a_document_is_minted_once() {
        two_docs().create_doc(OTHER, None);
    }

    /// A version is a document minted once too: a version into a document
    /// the shadow holds is stopped, never laid over it.
    #[test]
    #[should_panic(expected = "a document is minted once: the shadow already holds 1.1.0.1.0.2")]
    fn a_version_is_minted_once() {
        two_docs().version(SOURCE, OTHER);
    }

    /// An edit of a document the shadow does not hold changes nothing: the
    /// document stays unheld and unlisted, holding neither text nor links,
    /// and the register and the last-written document stay where they were.
    #[test]
    fn an_edit_of_an_unheld_document_changes_nothing() {
        const UNHELD: &str = "1.1.0.1.0.9";
        let mut s = two_docs();
        s.insert(SOURCE, 1, b"AB");
        s.insert(UNHELD, 1, b"XY");
        s.seat_link(UNHELD);
        s.delete(UNHELD, 1, 1);
        s.pivot(UNHELD, 1, 2, 3);
        s.swap(UNHELD, 1, 2, 2, 3);
        s.set_current(UNHELD);
        assert!(!s.knows(UNHELD));
        assert_eq!(s.created(), [SOURCE, OTHER]);
        assert_eq!((s.text_len(UNHELD), s.link_count(UNHELD)), (0, 0));
        assert_eq!(s.current().as_deref(), Some(OTHER));
        assert_eq!(s.last_written.as_deref(), Some(SOURCE));
    }
}
