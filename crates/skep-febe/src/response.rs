//! The marshaled [`Response`] — consolidated by shape; every write carries the
//! committed `Seq`, every read the snapshot `Seq` (ASN-0134 A1/A2/V1).

use skep_address::{Address, SpanSet};
use skep_arrangement::Run;
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link};
use skep_retrieval::{CompareReport, Deletions, Delivery};

use crate::reject::Rejection;

/// The marshaled response. `Response` deliberately derives **no** `Clone`
/// (§7): the idempotency cache stores a small op-kind-tagged `Cached` essence,
/// never a whole `Response`, so no transitively heavy `Clone` bound is forced
/// onto M6's/M7's payload types.
pub enum Response {
    /// delete/copy/rearrange — committed at `at` (A7).
    Ack { at: Seq },
    /// create/insert/version/makelink/emit/nullify/sup/fork/delegate/node.
    AckAddr { addr: Address, at: Seq },
    /// editlink: the successor link and its supersession claim.
    AckEdit { successor: Address, claim: Address, at: Seq },
    /// RETRIEVEV delivery.
    Delivery { items: Delivery, as_of: Seq },
    /// vspan/vspanset/project.
    SpanSet { set: SpanSet, as_of: Seq },
    /// origins/docs-containing/findlinks.
    Addrs { addrs: Vec<Address>, as_of: Seq },
    /// next-account-prefix / principal-prefix (`None` = absent/ineligible).
    MaybeAddr { addr: Option<Address>, as_of: Seq },
    /// count_v / count_ftt.
    Count { n: usize, as_of: Seq },
    /// window_v / window_ftt.
    Page { window: Window, as_of: Seq },
    /// RETRIEVEENDSETS pairs.
    Endsets { pairs: Vec<(usize, Endset)>, as_of: Seq },
    /// V→I image.
    Runs { runs: Vec<Run>, as_of: Seq },
    /// discoverable_from.
    Bool { val: bool, as_of: Seq },
    /// readlink (`None` = ⊥).
    LinkValue { link: Option<Link>, as_of: Seq },
    /// followlink — the one response carrying a `Result` in-band, by design:
    /// ⟨⟩ ≠ ⊥ is a defined FOLLOWLINK answer (§2); `Invalid` is a query
    /// result, not a lifecycle failure, and is never lowered to a
    /// [`Rejection`].
    Follow { result: Result<SpanSet, Invalid>, as_of: Seq },
    /// SHOWDELETIONS report.
    Deletions { rep: Deletions, as_of: Seq },
    /// COMPARE report.
    Compare { rep: CompareReport, as_of: Seq },
    /// delete_orphans preview.
    Orphans { report: OrphanReport, as_of: Seq },
    /// in_claims / out_claims.
    Claims { claims: Vec<SupClaim>, as_of: Seq },
    /// The never-silent surface: every failure of a parsed `Op` (Invariants).
    Rejected(Rejection),
}

impl Response {
    /// The only responses a lost acknowledgment can duplicate — the sole
    /// cache-admissible shapes (§1 step (d), §7).
    pub(crate) fn is_committed_write(&self) -> bool {
        matches!(self, Response::Ack { .. } | Response::AckAddr { .. } | Response::AckEdit { .. })
    }
}
