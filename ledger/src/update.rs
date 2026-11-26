use lb_core::{
    events::Events,
    mantle::batch::{self, DeferredProofs},
};

use crate::LedgerState;

pub struct PreparedUpdate<Id> {
    id: Id,
    state: LedgerState,
    events: Events,
    deferred_proofs: DeferredProofs,
}

impl<Id> PreparedUpdate<Id> {
    #[must_use]
    pub const fn new(
        id: Id,
        state: LedgerState,
        events: Events,
        deferred_proofs: DeferredProofs,
    ) -> Self {
        Self {
            id,
            state,
            events,
            deferred_proofs,
        }
    }

    /// Verifies the deferred proofs of the update as a batch.
    ///
    /// This is the way to commit an update for a block that this node has
    /// not verified yet, such as a block received from a peer.
    pub fn verify_batch_proofs(self) -> Result<VerifiedUpdate<Id>, batch::Error> {
        let (update, deferred_proofs) = self.into_parts();
        deferred_proofs.verify()?;
        Ok(update)
    }

    /// Takes the deferred proofs of the update as valid, without verifying
    /// them.
    ///
    /// The stateful checks of every operation have already run when the
    /// update was prepared, so only the deferred proofs are skipped.
    ///
    /// Use this only for a block that this node fully verified, proofs
    /// included, before storing it, such as when stored blocks are replayed
    /// on restart. A block received from a peer must go through
    /// [`Self::verify_batch_proofs`].
    #[must_use]
    pub fn trust_batch_proofs(self) -> VerifiedUpdate<Id> {
        let (update, _deferred_proofs) = self.into_parts();
        update
    }

    fn into_parts(self) -> (VerifiedUpdate<Id>, DeferredProofs) {
        let Self {
            id,
            state,
            events,
            deferred_proofs,
        } = self;
        (VerifiedUpdate { id, state, events }, deferred_proofs)
    }
}

/// An update whose deferred proofs were either verified by
/// [`PreparedUpdate::verify_batch_proofs`] or trusted by
/// [`PreparedUpdate::trust_batch_proofs`], so it can be committed.
pub struct VerifiedUpdate<Id> {
    pub id: Id,
    pub state: LedgerState,
    pub events: Events,
}

#[cfg(test)]
mod tests {
    use lb_core::{
        events::{Event, HeaderEvent},
        mantle::batch::DeferredZkSig,
        sdp::{DeclarationId, ServiceType},
    };
    use lb_groth16::Fr;
    use lb_key_management_system_keys::keys::{ZkKey, public_inputs_from_pks};
    use num_bigint::BigUint;

    use super::*;
    use crate::{
        ConsensusExcludedKeys,
        cryptarchia::tests::{GENESIS_POW_REWARD_POOL, config, utxo},
    };

    const ID: [u8; 32] = [1; 32];

    #[test]
    fn verify_batch_proofs_carries_the_update_through() {
        let state = LedgerState::from_utxos(
            [utxo()],
            &config(),
            GENESIS_POW_REWARD_POOL,
            &ConsensusExcludedKeys::empty(),
        );
        let utxos_root = state.latest_utxos().root();
        let update = PreparedUpdate::new(
            ID,
            state,
            Events::from(header_event()),
            std::iter::once(valid_zk_sig()).collect(),
        );

        let update = update.verify_batch_proofs().expect("must succeed");
        assert_eq!(update.id, ID);
        assert_eq!(update.state.latest_utxos().root(), utxos_root);
        assert_eq!(update.events.len(), 1);
    }

    #[test]
    fn verify_batch_proofs_rejects_invalid_deferred_proof() {
        let update = PreparedUpdate::new(
            ID,
            LedgerState::from_utxos(
                [utxo()],
                &config(),
                GENESIS_POW_REWARD_POOL,
                &ConsensusExcludedKeys::empty(),
            ),
            Events::new(),
            std::iter::once(invalid_zk_sig()).collect(),
        );
        assert!(matches!(
            update.verify_batch_proofs(),
            Err(batch::Error::InvalidZkSignatures)
        ));
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "Tests the method that is restricted to stored-block replay."
    )]
    fn trust_batch_proofs_skips_the_deferred_proofs() {
        let state = LedgerState::from_utxos(
            [utxo()],
            &config(),
            GENESIS_POW_REWARD_POOL,
            &ConsensusExcludedKeys::empty(),
        );
        let utxos_root = state.latest_utxos().root();
        let update = PreparedUpdate::new(
            ID,
            state,
            Events::from(header_event()),
            std::iter::once(invalid_zk_sig()).collect(),
        );

        // The invalid proof is not verified, so the update is carried through.
        let update = update.trust_batch_proofs();
        assert_eq!(update.id, ID);
        assert_eq!(update.state.latest_utxos().root(), utxos_root);
        assert_eq!(update.events.len(), 1);
    }

    fn header_event() -> Event {
        HeaderEvent::SdpNoteUnlocked {
            note_id: utxo().id(),
            service_type: ServiceType::BlendNetwork,
            declaration_id: DeclarationId([2; 32]),
        }
        .into()
    }

    fn valid_zk_sig() -> DeferredZkSig {
        zk_sig(1, 1)
    }

    fn invalid_zk_sig() -> DeferredZkSig {
        zk_sig(1, 2)
    }

    /// If `msg == msg_for_input`, a valid sig is produced.
    /// Otherwise, an invalid sig is produced.
    fn zk_sig(msg: u64, msg_for_input: u64) -> DeferredZkSig {
        let key = ZkKey::from(BigUint::from(1u8));
        let signature = ZkKey::multi_sign(std::slice::from_ref(&key), &Fr::from(msg)).unwrap();
        let inputs =
            public_inputs_from_pks(Fr::from(msg_for_input).into(), &[key.to_public_key()]).unwrap();
        DeferredZkSig::new(*signature.as_proof(), inputs)
    }
}
