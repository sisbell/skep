//! The UPLOAD FAMILY's admission at the session layer (D12; PUB-6.35's I10;
//! the media register's M-I6 (b); sweep-5 media-leak
//! `upload-admitted-where-no-op-would-be`): who may take bytes into the
//! board's blob store at all, asked by every method of `/blob/upload` before
//! the media resource is consulted. The family commits nothing to the
//! journal, so it is no write sequence; it is gated by the session layer as
//! one is, its refusals riding `403 upload_refused` (wire.md §Media).

use skep_address::Level;
use skep_identity::HasIdentity;
use skep_namespace::{HasM3, PrincipalId};

use super::CredentialRefusal;
use crate::auth::session::Actor;
use crate::World;

/// Why the session layer refuses an act of the upload family — the `detail`
/// of `403 upload_refused`, in the order [`upload_admission`] asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadRefusal {
    /// No live session: the guest, at every act of the family.
    Unauthenticated,
    /// The board is unclaimed: the upload is admitted on a claimed board
    /// alone (M-I6 (b), PUB-6.35's I10 cited) — every method of the family,
    /// the deposit read included.
    ClaimFirst,
    /// A NODE-TIER principal — principal 0 of this node or of a sub-node,
    /// which owns no documents — refused before any body byte, so no deposit
    /// stands that no account's scope counts.
    NodeTier,
}

impl UploadRefusal {
    /// The `detail` token. `claim_first` is the pre-claim gate's own, spelled
    /// through the credential family as the registry family spells the tokens
    /// it shares (`RegistryRefusal::token`).
    pub(crate) fn token(self) -> String {
        match self {
            UploadRefusal::Unauthenticated => "unauthenticated".into(),
            UploadRefusal::ClaimFirst => CredentialRefusal::ClaimFirst.token(),
            UploadRefusal::NodeTier => "node_tier".into(),
        }
    }
}

/// THE ADMISSION, in its order — a guest, then an unclaimed board, then a
/// node-tier principal — off `world`, the head snapshot the route took, whose
/// identity slice and principal registry are one committed state. `Ok` is
/// the principal every later step keys its records to.
pub(crate) fn upload_admission(
    world: &World,
    actor: &Actor,
) -> Result<PrincipalId, UploadRefusal> {
    let Actor::Principal(binding) = actor else {
        return Err(UploadRefusal::Unauthenticated);
    };
    if world.identity().claimant().is_none() {
        return Err(UploadRefusal::ClaimFirst);
    }
    let account_tier = world
        .m3()
        .principal_prefix(binding.principal)
        .is_some_and(|prefix| prefix.level() == Level::Account);
    if !account_tier {
        return Err(UploadRefusal::NodeTier);
    }
    Ok(binding.principal)
}

#[cfg(test)]
mod tests {
    use skep_febe::SessionId;
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::BOOTSTRAP_PRINCIPAL;

    use super::*;
    use crate::auth::session::{GuestReason, Scope, SessionBinding};

    /// THE ADMISSION'S ORDER AND ITS TOKENS, over the genesis world — an
    /// unclaimed board on which principal 0 sits at the node `1`: the guest is
    /// refused `unauthenticated` ahead of the board's state, and principal 0 —
    /// node-tier, so refused `node_tier` on a claimed board (the wire
    /// fixture's `the_session_layer_gate`) — is refused `claim_first` here,
    /// the claim asked ahead of the tier. The tokens are the wire's (wire.md
    /// §Media), `claim_first` the credential family's own.
    #[test]
    fn the_admission_asks_the_actor_then_the_claim_then_the_tier() {
        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        let guest = Actor::Guest(GuestReason::NoToken);
        assert_eq!(upload_admission(world, &guest), Err(UploadRefusal::Unauthenticated));
        assert_eq!(
            world.m3().principal_prefix(BOOTSTRAP_PRINCIPAL).map(|prefix| prefix.level()),
            Some(Level::Node),
            "the premise: principal 0 is node-tier"
        );
        let boot = Actor::Principal(SessionBinding {
            sid: SessionId::GUEST,
            principal: BOOTSTRAP_PRINCIPAL,
            signer: None,
            scope: Scope::Full,
        });
        assert_eq!(
            upload_admission(world, &boot),
            Err(UploadRefusal::ClaimFirst),
            "the claim is asked ahead of the tier"
        );
        let tokens: Vec<String> =
            [UploadRefusal::Unauthenticated, UploadRefusal::ClaimFirst, UploadRefusal::NodeTier]
                .into_iter()
                .map(UploadRefusal::token)
                .collect();
        assert_eq!(tokens, ["unauthenticated", "claim_first", "node_tier"]);
    }
}
