//! §Core data model / §Internal 4 — the DefMemo: M9's one interior-mutable
//! hint, a per-start cache of PERMANENT verdicts about stored predicate
//! definitions. It holds no authority: every entry is recomputable from the
//! def's immutable content plus M7's audit slice, and a rebuilt memo answers
//! every question the old one did.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use skep_address::{Address, Tumbler};

use crate::check::TypedTerm;

/// A def-status answer, distinguishing CVALID (0)'s two `None` causes:
/// `Poisoned` (ever-registered, content undisciplined — PR-DISC breach) and
/// `Unregistered` (never registered at the answering snapshot). A `Defined`
/// answer is the memo's own `Arc` of the def's checked term — its signature
/// (`params`/`result_sort`) and its `Reg`-expanded evaluable body.
pub(crate) enum DefStatus {
    Defined(Arc<TypedTerm>),
    Poisoned,
    Unregistered,
}

/// A cached verdict. Both variants are PERMANENT: content is immutable and
/// ever-registration is monotone, so a `Defined` entry can never be
/// contradicted, and a `Poisoned` one is freeze-on-breach (§Internal 4).
enum MemoEntry {
    Defined(Arc<TypedTerm>),
    Poisoned,
}

/// The verdict on an ever-registered start whose immutable content fails the
/// PR-ENC parse or WT — the breach the poison records.
pub(crate) struct Breach;

/// The memo. THE POLICY, in one place: a start is cached only once it is
/// ever-registered (a never-registered start must surface a later
/// registration, so it is never cached); the first fill wins and every later
/// fill of the same start is a no-op (racing fills derive the same verdict
/// from the same immutable content, so first-wins loses nothing); nothing is
/// ever evicted or overwritten. A `RwLock`, never a `RefCell`: the `&self`
/// signature/define paths of a shared `Coordinator` need `Sync`.
pub(crate) struct DefMemo(RwLock<HashMap<Tumbler, MemoEntry>>);

impl DefMemo {
    pub(crate) fn new() -> DefMemo {
        DefMemo(RwLock::new(HashMap::new()))
    }

    /// The cached verdict, if any — `None` means "derive it", never "not a
    /// def".
    pub(crate) fn get(&self, start: &Address) -> Option<DefStatus> {
        let memo = self.0.read().expect("DefMemo lock");
        memo.get(start.tumbler()).map(|e| match e {
            MemoEntry::Defined(d) => DefStatus::Defined(Arc::clone(d)),
            MemoEntry::Poisoned => DefStatus::Poisoned,
        })
    }

    /// Record a verdict for an ever-registered start — first fill wins — and
    /// answer with whatever the memo now holds for it.
    pub(crate) fn fill(&self, start: &Address, verdict: Result<TypedTerm, Breach>) -> DefStatus {
        let mut memo = self.0.write().expect("DefMemo lock");
        let entry = memo.entry(start.tumbler().clone()).or_insert_with(|| match verdict {
            Ok(t) => MemoEntry::Defined(Arc::new(t)),
            Err(Breach) => MemoEntry::Poisoned,
        });
        match entry {
            MemoEntry::Defined(d) => DefStatus::Defined(Arc::clone(d)),
            MemoEntry::Poisoned => DefStatus::Poisoned,
        }
    }
}
