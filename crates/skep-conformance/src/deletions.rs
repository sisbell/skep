//! Deleted content's I-history (operator ruling 10): every content-subspace
//! deletion of one scenario, captured at delete time and keyed by the golden
//! document it left — the bytes removed and the I-extents they occupied,
//! imaged while the arrangement still spoke for them. Deleted content stays
//! findable through these spans, never by loosening V-queries; the searches
//! read them here, and the play pass's delete records them.

use skep_address::Span;

use crate::tum::{span_elem_width, subspan};

/// One deletion: the golden doc it left, the bytes removed, and the I-extent
/// runs those bytes occupied.
#[derive(Debug)]
struct DeletedRegion {
    doc: String,
    bytes: Vec<u8>,
    ispans: Vec<Span>,
}

/// A scenario's deletions, in execution order.
#[derive(Debug, Default)]
pub struct Deletions {
    regions: Vec<DeletedRegion>,
}

impl Deletions {
    /// Record one deletion from golden `doc`: the removed bytes and the
    /// I-spans they occupied. An empty removal is no history.
    pub fn record(&mut self, doc: &str, bytes: Vec<u8>, ispans: Vec<Span>) {
        if bytes.is_empty() {
            return;
        }
        self.regions.push(DeletedRegion { doc: doc.to_string(), bytes, ispans });
    }

    /// Every captured I-span of a document's deleted content — the
    /// I-coverage stand-in for a whole-extent query aimed at a doc whose
    /// current extent no longer holds what the golden searched.
    pub fn ispans_of(&self, doc: &str) -> Vec<Span> {
        self.regions
            .iter()
            .filter(|r| r.doc == doc)
            .flat_map(|r| r.ispans.iter().cloned())
            .collect()
    }

    /// The deleted bytes of a document, latest deletion first — for
    /// re-locating a doc-aimed search's content in the docs that still hold
    /// it live.
    pub fn bytes_of(&self, doc: &str) -> Vec<Vec<u8>> {
        self.regions.iter().rev().filter(|r| r.doc == doc).map(|r| r.bytes.clone()).collect()
    }

    /// Locate `needle` inside any captured deletion and slice out its exact
    /// I-spans — the I-history reach for a search whose text no live V-space
    /// speaks anymore. First (newest-deletion-first) hit wins.
    pub fn locate(&self, needle: &[u8]) -> Option<Vec<Span>> {
        if needle.is_empty() {
            return None;
        }
        for rec in self.regions.iter().rev() {
            let Some(p) = rec.bytes.windows(needle.len()).position(|w| w == needle) else {
                continue;
            };
            // Walk the record's runs, slicing the [p, p+len) byte window.
            let (mut off, mut remaining, mut cursor) = (p as u64, needle.len() as u64, Vec::new());
            for sp in &rec.ispans {
                let w = span_elem_width(sp).unwrap_or(0);
                if off >= w {
                    off -= w;
                    continue;
                }
                let take = (w - off).min(remaining);
                if let Some(sub) = subspan(sp, off, take) {
                    cursor.push(sub);
                } else {
                    cursor.clear();
                    break;
                }
                remaining -= take;
                off = 0;
                if remaining == 0 {
                    break;
                }
            }
            if remaining == 0 && !cursor.is_empty() {
                return Some(cursor);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tum::tum;

    /// An element-level run of `w` elements from `start`.
    fn run(start: &[u64], w: u64) -> Span {
        let mut width = vec![0; start.len() - 1];
        width.push(w);
        Span::new(tum(start), tum(&width)).expect("an element-level run")
    }

    /// A needle deleted across two runs slices out of both, exactly as wide
    /// as it is; the history answers per document, newest deletion first.
    #[test]
    fn a_deleted_needle_slices_out_of_the_runs_that_held_it() {
        let mut d = Deletions::default();
        let (a, b) = (run(&[1, 0, 1, 0, 3, 0, 1, 1], 3), run(&[1, 0, 1, 0, 4, 0, 1, 5], 3));
        d.record("doc", b"ABCDEF".to_vec(), vec![a.clone(), b.clone()]);
        d.record("doc", b"XY".to_vec(), vec![run(&[1, 0, 1, 0, 3, 0, 1, 9], 2)]);
        d.record("doc", Vec::new(), vec![run(&[1, 0, 1, 0, 3, 0, 1, 20], 1)]);

        assert_eq!(
            d.locate(b"CDE"),
            Some(vec![run(&[1, 0, 1, 0, 3, 0, 1, 3], 1), run(&[1, 0, 1, 0, 4, 0, 1, 5], 2)])
        );
        assert_eq!(d.locate(b"QQ"), None);
        assert_eq!(d.bytes_of("doc"), vec![b"XY".to_vec(), b"ABCDEF".to_vec()]);
        assert_eq!(d.ispans_of("doc").len(), 3, "the empty removal left no history");
        assert!(d.ispans_of("other").is_empty());
        assert!(d.ispans_of("doc").starts_with(&[a, b]));
    }
}
