//! The typed rejections of M3's public surface (§Public interface). Where an
//! op pins the order its guards run in, the variants are declared in that
//! order — [`DelegateError`] (§6) and [`NodeError`] (§7) both do, so the
//! declaration reads as the contract.

use std::error::Error;
use std::fmt;

use skep_address::GateViolation;

/// Frontier-mint rejection (§A). The structural preconditions are the only
/// active gates (§4); `Gate` is the M1 inc-gate (B6/TA5a) routed defensively —
/// it fires only on a corrupted frontier, never on a live path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// `mint_content`/`mint_link`: home is not a registered Document (P6/C2/L1a).
    HomeNotRegistered,
    /// `mint_version`: source is NOT a registered Document (V-WF) — covers both
    /// an unregistered address AND a registered non-document.
    SourceNotRegistered,
    /// `mint_document`: target is not a registered Account (P8/CND.pre) —
    /// covers both unregistered AND non-account.
    NotAnAccount,
    /// M1's TA5a inc gate refused (B6) — defensive: corrupted frontier state.
    Gate(GateViolation),
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintError::HomeNotRegistered => {
                f.write_str("mint: home is not a registered Document (P6/C2/L1a)")
            }
            MintError::SourceNotRegistered => f.write_str(
                "mint_version: source is not a registered Document (V-WF; covers unregistered and non-document alike)",
            ),
            MintError::NotAnAccount => f.write_str(
                "mint_document: target is not a registered Account (P8; covers unregistered and non-account alike)",
            ),
            MintError::Gate(e) => write!(f, "mint: M1 inc gate refused (B6/TA5a, defensive): {e}"),
        }
    }
}

impl Error for MintError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            MintError::Gate(e) => Some(e),
            _ => None,
        }
    }
}

/// Document-baptism rejection, shared by the two ops that create a document
/// — `create_new_document` and `fork` (§B). "Not an account" and "not
/// registered" BOTH surface via `Mint(MintError::NotAnAccount)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateDocumentError {
    /// Caller is not the effective owner ω of the target (O5) — authorization
    /// is by ω (longest match), never bare prefix containment.
    NotOwner,
    /// The op's mint failed structurally.
    Mint(MintError),
}

impl fmt::Display for CreateDocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateDocumentError::NotOwner => f.write_str(
                "caller is not the effective owner (ω) of the target (O5; ω arbitrates, never bare containment)",
            ),
            CreateDocumentError::Mint(e) => write!(f, "document mint failed: {e}"),
        }
    }
}

impl Error for CreateDocumentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CreateDocumentError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

/// `delegate` rejection — the O15 five-condition gate with (iii) NARROWED to
/// `zeros == 1` (§6 / Conflicts §7), PLUS id-freshness PLUS P8 PLUS next-form.
///
/// The variants are declared in `delegate`'s PINNED rejection order (§6):
/// `NotValid` and `NotAccountTier` are pure pre-work — both `Rejected` with
/// NO transaction opened — and the rest are the in-closure gate, in the order
/// it evaluates them. A multiply-defective input earns the FIRST applicable
/// rejection; conformance tests and M10's error handling may rely on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateError {
    /// O15(v) validity: `new_prefix` is not T4-valid.
    NotValid,
    /// O15(iii), narrowed `≤1 → ==1` and hoisted to pre-work: `new_prefix` is
    /// node-tier (zeros = 0) or document-tier (zeros ≥ 2), not account-tier.
    NotAccountTier,
    /// The delegator id names no principal (§5 scan).
    DelegatorUnknown,
    /// O15(i): the delegator's prefix is not a strict ancestor of `new_prefix`.
    NotAncestor,
    /// O15(ii): the delegator is not the effective owner ω of `new_prefix`.
    NotAuthorized,
    /// O15(iv): a principal already sits strictly under `new_prefix`.
    NotTopDown,
    /// O15(v) freshness: `new_prefix` is already allocated.
    NotFresh,
    /// `new_id` is already carried by a principal — id-injectivity, the
    /// id-axis mirror of O1b (§6).
    DuplicateId,
    /// P8: the parent of `new_prefix` is not a registered entity (Conflicts §5).
    ParentNotRegistered,
    /// O17c: `new_prefix` is not the namespace's next address — obtain the
    /// exact value from `next_account_prefix` instead of guess-and-retry.
    NotNextForm,
}

impl fmt::Display for DelegateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DelegateError::NotValid => "delegate: new_prefix is not T4-valid (O15 v)",
            DelegateError::NotAccountTier => {
                "delegate: new_prefix is not account-tier — zeros must be exactly 1 (O15 iii, narrowed)"
            }
            DelegateError::DelegatorUnknown => "delegate: delegator id names no principal",
            DelegateError::NotAncestor => {
                "delegate: delegator's prefix is not a strict ancestor of new_prefix (O15 i)"
            }
            DelegateError::NotAuthorized => {
                "delegate: delegator is not the effective owner ω of new_prefix (O15 ii)"
            }
            DelegateError::NotTopDown => {
                "delegate: a principal already sits strictly under new_prefix (O15 iv)"
            }
            DelegateError::NotFresh => "delegate: new_prefix is already allocated (O15 v)",
            DelegateError::DuplicateId => {
                "delegate: new_id is already carried by a principal (id-injectivity)"
            }
            DelegateError::ParentNotRegistered => {
                "delegate: the parent of new_prefix is not a registered entity (P8)"
            }
            DelegateError::NotNextForm => {
                "delegate: new_prefix is not the namespace's next address (O17c; peek next_account_prefix)"
            }
        })
    }
}

impl Error for DelegateError {}

/// `register_node` rejection (ASN-0047 NodeBaptism; §7). The variants are
/// declared in the order the guards run: `NotValid` and `NotNode` are pure
/// pre-work — `Rejected` with NO transaction opened — and the two registry
/// reads follow, under the held node key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// The supplied address is not T4-valid.
    NotValid,
    /// The supplied address is not node-level (zeros ≠ 0).
    NotNode,
    /// The node is already registered — surfaced (rather than silently
    /// coalescing) under the held coarse node-registry key (§7/§8).
    NotFresh,
    /// Bootstrap lineage `[1] ≼ addr` fails.
    NotDescendantOfBootstrap,
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NodeError::NotValid => "register_node: addr is not T4-valid",
            NodeError::NotNode => "register_node: addr is not node-level",
            NodeError::NotFresh => "register_node: node is already registered",
            NodeError::NotDescendantOfBootstrap => {
                "register_node: addr is not a descendant of the bootstrap node [1]"
            }
        })
    }
}

impl Error for NodeError {}
