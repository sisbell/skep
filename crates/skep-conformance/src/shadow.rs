//! The golden-side shadow: per golden document, the byte sequence its
//! content subspace holds after each recorded edit, plus the symbolic-name
//! registry ("source", "target", "original", "version", "doc1"…) the
//! recording scripts used in place of addresses.
//!
//! The shadow exists ONLY to translate text-denoted references the goldens
//! use ("source_text": locate a substring; "delete by text"; append-at-end
//! positions; whole-extent spans). It is computed from the RECORDED ops
//! alone — never from skep responses — so translation stays independent of
//! skep's behavior and a skep divergence cannot bend later translations.
//! It replicates exactly the sequence bookkeeping the recording scripts
//! themselves did; it adds no semantics of its own.

use std::collections::BTreeMap;

/// Per-document shadow state, keyed by GOLDEN docid string.
#[derive(Default)]
pub struct DocShadow {
    /// Content-subspace bytes, ordinal i ↦ text[i-1].
    pub text: Vec<u8>,
    /// Link-subspace occupancy count (links homed here, in creation order).
    pub links: u64,
}

#[derive(Default)]
pub struct Shadow {
    docs: BTreeMap<String, DocShadow>,
    /// Symbolic name → golden docid ("source" → "1.1.0.1.0.1").
    names: BTreeMap<String, String>,
    /// Golden docids in creation order (for "doc1"/"first"/"second" fallbacks).
    pub created: Vec<String>,
    /// The golden id of the most recently created link (implicit follow_link
    /// target in some scenarios).
    pub last_link: Option<String>,
    /// version source memo: version docid → source docid.
    pub version_of: BTreeMap<String, String>,
}

impl Shadow {
    pub fn new() -> Shadow {
        Shadow::default()
    }

    pub fn create_doc(&mut self, golden: &str, name: Option<&str>) {
        self.docs.entry(golden.to_string()).or_default();
        self.created.push(golden.to_string());
        if let Some(n) = name {
            self.bind_name(n, golden);
        }
    }

    pub fn bind_name(&mut self, name: &str, golden: &str) {
        self.names.entry(name.to_string()).or_insert_with(|| golden.to_string());
    }

    /// Resolve a doc reference: a dotted address passes through; a symbolic
    /// name resolves via the registry, then via the recording scripts'
    /// standing conventions (documented here because the JSON leaves them
    /// implicit): "source"/"doc1"/"doc"/"original" → first created,
    /// "target"/"doc2" → second, "doc3" → third, "version" → the last
    /// version created. `None` when nothing fits — the caller records it.
    pub fn resolve_doc(&self, r: &str) -> Option<String> {
        if crate::alpha::looks_like_address(r) {
            return Some(r.to_string());
        }
        if let Some(g) = self.names.get(r) {
            return Some(g.clone());
        }
        let nth = |i: usize| self.created.get(i).cloned();
        match r {
            "source" | "doc" | "doc1" | "original" | "first" | "home" => nth(0),
            "target" | "doc2" | "second" | "dest" | "destination" => nth(1),
            "doc3" | "third" => nth(2),
            "version" | "copy" => self
                .version_of
                .keys()
                .last()
                .cloned()
                .or_else(|| nth(1)),
            _ => None,
        }
    }

    pub fn doc(&self, golden: &str) -> Option<&DocShadow> {
        self.docs.get(golden)
    }

    pub fn text_len(&self, golden: &str) -> u64 {
        self.docs.get(golden).map(|d| d.text.len() as u64).unwrap_or(0)
    }

    pub fn link_count(&self, golden: &str) -> u64 {
        self.docs.get(golden).map(|d| d.links).unwrap_or(0)
    }

    /// All docids currently shadowed (creation order).
    pub fn all_docs(&self) -> Vec<String> {
        self.created.clone()
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
            t.windows(n.len())
                .position(|w| w == n)
                .map(|p| (g.to_string(), p as u64 + 1))
        };
        match doc {
            Some(g) => hit(g),
            None => self.created.iter().find_map(|g| hit(g)),
        }
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
    /// udanax's CREATENEWVERSION copies both subspaces (the golden
    /// expectations reflect that; whether skep does is exactly what the
    /// comparisons will show).
    pub fn version(&mut self, src: &str, new_golden: &str) {
        let (text, links) = match self.docs.get(src) {
            Some(d) => (d.text.clone(), d.links),
            None => (Vec::new(), 0),
        };
        self.docs.insert(new_golden.to_string(), DocShadow { text, links });
        self.created.push(new_golden.to_string());
        self.version_of.insert(new_golden.to_string(), src.to_string());
        self.bind_name("version", new_golden);
        // Late-bind "original" to the source if nothing claimed it yet.
        let src_owned = src.to_string();
        self.names.entry("original".to_string()).or_insert(src_owned);
    }

    pub fn seat_link(&mut self, home_golden: &str) {
        self.docs.entry(home_golden.to_string()).or_default().links += 1;
    }
}
