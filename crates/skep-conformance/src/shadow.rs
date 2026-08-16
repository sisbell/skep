//! The golden-side shadow: per golden document, the byte sequence its
//! content subspace holds after each recorded edit, plus the symbolic-name
//! registry ("source", "target", "doc1"…) and the CURRENT-DOCUMENT REGISTER
//! the recording scripts kept implicitly (ops without a `doc` field target
//! the most recently *named* document — named by a create/open/version
//! result, an explicit doc field, or an expectation's docid).
//!
//! The shadow exists ONLY to translate text-denoted references the goldens
//! use. It is computed from the RECORDED ops (plus the grounding pre-pass's
//! inferred setup) — never from skep responses — so translation stays
//! independent of skep's behavior and a skep divergence cannot bend later
//! translations.

use std::collections::BTreeMap;

/// Per-document shadow state, keyed by GOLDEN docid string.
#[derive(Default, Clone)]
pub struct DocShadow {
    /// Content-subspace bytes, ordinal i ↦ text[i-1].
    pub text: Vec<u8>,
    /// Link-subspace occupancy count (links homed here, in creation order).
    pub links: u64,
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

#[derive(Default, Clone)]
pub struct Shadow {
    docs: BTreeMap<String, DocShadow>,
    /// Symbolic name → golden docid ("source" → "1.1.0.1.0.1").
    names: BTreeMap<String, String>,
    /// Golden docids in creation order (for "doc1"/"first"/"second" fallbacks).
    pub created: Vec<String>,
    /// The current-document register (see module docs).
    current: Option<String>,
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

    pub fn create_doc(&mut self, golden: &str, name: Option<&str>) {
        self.docs.entry(golden.to_string()).or_default();
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

    pub fn bind_name(&mut self, name: &str, golden: &str) {
        self.names.entry(name.to_string()).or_insert_with(|| golden.to_string());
    }

    /// The current-document register.
    pub fn scoped(&self) -> Option<String> {
        self.current.clone().or_else(|| self.created.last().cloned())
    }

    /// Point the register at a document (any op that names one calls this).
    pub fn set_current(&mut self, golden: &str) {
        if self.docs.contains_key(golden) {
            self.current = Some(golden.to_string());
        }
    }

    /// Resolve a doc reference: a dotted address passes through; a symbolic
    /// name resolves via the registry, then via the recording scripts'
    /// standing conventions: "source"/"doc1"/"doc"/"original"/A → first
    /// created, "target"/"doc2"/B → second, "doc3"/C → third, "version" →
    /// the last version created, "same doc"/"current" → the register.
    /// `None` when nothing fits — the caller records it.
    pub fn resolve_doc(&self, r: &str) -> Option<String> {
        if crate::fields::is_link_address(r) {
            return None; // a link id is never a document reference
        }
        if crate::tum::parse_dotted(r).is_some() {
            return Some(r.to_string());
        }
        if let Some(g) = self.names.get(r) {
            return Some(g.clone());
        }
        let nth = |i: usize| self.created.get(i).cloned();
        // Role names prefer a REGISTERED name containing the role over the
        // positional convention: a scenario naming its fourth doc
        // "shared_target" means THAT doc by "target", not doc #2
        // (links/search_multiple_links_selective_removal).
        match r {
            "source" | "doc" | "doc1" | "original" | "first" | "home" | "A" | "a" => {
                self.find_named_containing_role(r).or_else(|| nth(0))
            }
            "target" | "doc2" | "second" | "dest" | "destination" | "B" | "b" => {
                self.find_named_containing_role(r).or_else(|| nth(1))
            }
            "doc3" | "third" | "C" | "c" => nth(2),
            "doc4" | "fourth" | "D" | "d" => nth(3),
            "same doc" | "current" | "this" | "self" => self.scoped(),
            "version" | "copy" => self.version_of.keys().last().cloned().or_else(|| nth(1)),
            _ => {
                // "sourceN"/"peripheralN" positional group names bound at
                // group creation; also substring name matches ("target" →
                // "shared_target") for `by`-clause tokens.
                self.find_named_containing(r)
            }
        }
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

    /// A doc whose registered name equals, contains, or is contained in `t`.
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

    pub fn doc(&self, golden: &str) -> Option<&DocShadow> {
        self.docs.get(golden)
    }

    pub fn knows(&self, golden: &str) -> bool {
        self.docs.contains_key(golden)
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
        self.docs.get(golden).map(|d| d.links).unwrap_or(0)
    }

    /// All docids currently shadowed (creation order).
    pub fn all_docs(&self) -> Vec<String> {
        self.created.clone()
    }

    /// Docs in creation order that hold content, excluding `not` — the
    /// "which doc did the script copy from" fallback.
    pub fn content_docs_except(&self, not: &str) -> Vec<String> {
        self.created
            .iter()
            .filter(|g| g.as_str() != not && self.text_len(g) > 0)
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

    /// Case-insensitive locate in ONE doc, returning the matched width (the
    /// label grammar says "after first" for content "First ").
    pub fn find_text_ci(&self, doc: &str, needle: &str) -> Option<(String, u64, u64)> {
        let d = self.docs.get(doc)?;
        let hay = String::from_utf8_lossy(&d.text).to_ascii_lowercase();
        let n = needle.to_ascii_lowercase();
        if n.is_empty() {
            return None;
        }
        hay.find(&n).map(|p| (doc.to_string(), p as u64 + 1, n.len() as u64))
    }

    // ── the edit mirror (pure sequence bookkeeping, matching the recorded
    //    udanax semantics: 1-based ordinals, half-open ranges) ──

    pub fn insert(&mut self, golden: &str, ord: u64, bytes: &[u8]) {
        let d = self.docs.entry(golden.to_string()).or_default();
        let i = (ord.saturating_sub(1) as usize).min(d.text.len());
        d.text.splice(i..i, bytes.iter().copied());
    }

    pub fn delete(&mut self, golden: &str, ord: u64, width: u64) {
        if let Some(d) = self.docs.get_mut(golden) {
            let s = (ord.saturating_sub(1) as usize).min(d.text.len());
            let e = (s + width as usize).min(d.text.len());
            d.text.drain(s..e);
        }
    }

    /// Bytes covered by [ord, ord+width) — for vcopy source capture.
    pub fn slice(&self, golden: &str, ord: u64, width: u64) -> Vec<u8> {
        match self.docs.get(golden) {
            Some(d) => {
                let s = (ord.saturating_sub(1) as usize).min(d.text.len());
                let e = (s + width as usize).min(d.text.len());
                d.text[s..e].to_vec()
            }
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
            }
        }
    }

    /// Version: the new doc mirrors the source's text AND link count —
    /// udanax's CREATENEWVERSION copies both subspaces. The Nth version
    /// created in a scenario binds the labels `vN`/`versionN` (the recording
    /// scripts' role names — versions/multiple_versions_same_source refers
    /// to its two unbound version results as "v1"/"v2"); `version` always
    /// names the LATEST version.
    pub fn version(&mut self, src: &str, new_golden: &str) {
        let (text, links) = match self.docs.get(src) {
            Some(d) => (d.text.clone(), d.links),
            None => (Vec::new(), 0),
        };
        self.docs.insert(new_golden.to_string(), DocShadow { text, links });
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

    pub fn seat_link(&mut self, home_golden: &str) {
        self.docs.entry(home_golden.to_string()).or_default().links += 1;
    }

    /// Register a created link's grounded endsets (play pass and setup steps
    /// call this on MakeLink success) — the traversal macros' hop-resolution
    /// world knowledge.
    pub fn record_link(
        &mut self,
        golden: &str,
        from: Vec<(String, u64, u64)>,
        to: Vec<(String, u64, u64)>,
    ) {
        if self.links.iter().any(|l| l.golden == golden) {
            return; // create_links:repeat re-registering the same id
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
