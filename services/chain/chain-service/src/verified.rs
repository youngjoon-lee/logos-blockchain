//! Block Header Verification, and the types of what passed it.

use lb_binary_codec::canonical::BinaryDecode;
use lb_core::{
    block::{Block, BlockTransactions, UncleHeaders, verify_header_alone, verify_header_signature},
    header::{Header, HeaderId},
    mantle::{
        TxHash,
        traits::{Hashable, PreverifiedMantleTransaction, StorageSize},
    },
    proofs::leader_proof::LeaderProof as _,
};
use lb_cryptarchia_engine::Slot;
use lb_key_management_system_keys::keys::Ed25519Signature;
use lb_ledger::{Ledger, LedgerError, PreparedUpdate, VerifiedUpdate};
use lb_storage_service::api::StorageApi;
use overwatch::DynError;

use crate::{Cryptarchia, Error};

/// A header that passed Block Header Verification, with the uncles and the
/// signature it was verified with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBlockHeader {
    header: Header,
    signature: Ed25519Signature,
    uncle_headers: UncleHeaders,
}

impl VerifiedBlockHeader {
    /// Verifies `header` with `uncle_headers` and `signature` against the
    /// block tree and the ledger of `cryptarchia` at `current_slot`.
    ///
    /// This checks the rules 5~10 of [Block Header Validation](https://lip.logos.co/blockchain/raw/cryptarchia-v1-protocol.html#block-header-validation),
    /// as well as the rules that need the header alone, and the signature.
    /// Rule 8 (Block is a descendant of LIB) is implied by Rule 7, since all
    /// forks deeper than LIB are pruned.
    pub(crate) fn new(
        header: Header,
        uncle_headers: UncleHeaders,
        signature: Ed25519Signature,
        cryptarchia: &Cryptarchia,
        current_slot: Slot,
    ) -> Result<Self, Error> {
        verify_header_alone(&header).map_err(Error::InvalidHeader)?;

        if cryptarchia
            .consensus
            .branches()
            .get(&header.parent())
            .is_none()
        {
            return Err(Error::ParentMissing {
                parent: header.parent(),
                info: Box::new(cryptarchia.info()),
            });
        }

        if header.slot() > current_slot {
            return Err(Error::FutureBlock {
                block_slot: header.slot(),
                current_slot,
            });
        }

        verify_header_signature(&header, &signature).map_err(|_| Error::InvalidSignature)?;

        let public_inputs = cryptarchia
            .ledger
            .leader_public(header.parent(), header.slot())
            .map_err(|err| match err {
                LedgerError::ParentNotFound(parent) => Error::ParentMissing {
                    parent,
                    info: Box::new(cryptarchia.info()),
                },
                LedgerError::InvalidSlot { parent, block } => Error::InvalidSlot { parent, block },
                err => Error::Ledger(err),
            })?;
        if !header.leader_proof().verify(&public_inputs) {
            return Err(Error::InvalidLeaderProof);
        }

        cryptarchia.verify_uncles(&header, &uncle_headers)?;

        Ok(Self {
            header,
            signature,
            uncle_headers,
        })
    }

    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    #[must_use]
    pub const fn uncle_headers(&self) -> &UncleHeaders {
        &self.uncle_headers
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
}

/// A [`Block`] whose header passed Block Header Verification.
///
/// Its transactions are not verified yet. They are verified against the ledger
/// while the block is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockWithVerifiedHeader<Tx>(Block<Tx>);

impl<Tx> BlockWithVerifiedHeader<Tx> {
    /// Assembles a block from `header` and `transactions`.
    ///
    /// # Errors
    ///
    /// Returns an error if the body root of `header` does not commit to its
    /// uncles and `transactions`. Whether `transactions` fit in the block's era
    /// is checked by the ledger when the block is applied.
    pub fn new(
        header: VerifiedBlockHeader,
        transactions: BlockTransactions<Tx>,
    ) -> Result<Self, lb_core::block::Error>
    where
        Tx: Hashable<Hash = TxHash> + StorageSize,
    {
        Block::validate_body_root(&header.header, &header.uncle_headers, &transactions)?;
        Ok(Self(Block::reconstruct(
            header.header,
            header.uncle_headers,
            transactions,
            header.signature,
        )))
    }

    #[must_use]
    pub const fn header(&self) -> &Header {
        self.0.header()
    }

    #[must_use]
    pub const fn uncle_headers(&self) -> &UncleHeaders {
        self.0.uncle_headers()
    }

    pub fn transactions_iter(&self) -> impl ExactSizeIterator<Item = &Tx> + '_ {
        self.0.transactions_iter()
    }

    /// Applies the block on top of its parent state in `ledger`, running the
    /// stateful checks of every operation. The deferred proofs are returned
    /// in the [`PreparedUpdate`], to be verified or trusted by the caller.
    pub(crate) fn prepare_update(
        &self,
        ledger: &Ledger<HeaderId>,
    ) -> Result<PreparedUpdate<HeaderId>, LedgerError<HeaderId>>
    where
        Tx: PreverifiedMantleTransaction + StorageSize + Clone,
    {
        let header = self.header();
        let leader_proof = header.leader_proof();
        ledger.prepare_update(
            header.id(),
            header.parent(),
            header.slot(),
            &leader_proof.entropy(),
            *leader_proof.voucher_cm(),
            &self.uncle_headers().slots(),
            self.transactions_iter().cloned(),
        )
    }
}

impl<Tx> From<BlockWithVerifiedHeader<Tx>> for Block<Tx> {
    fn from(block: BlockWithVerifiedHeader<Tx>) -> Self {
        block.0
    }
}

/// A [`Block`] read from the storage of this node.
///
/// This node fully verified the block before storing it: the header, the
/// transactions, and all their proofs. So its header is taken as verified, and
/// its deferred proofs are not verified again when it is applied. The stateful
/// checks of its transactions still run while it is applied.
///
/// It can be created only by reading the block from storage. A block received
/// from a peer must never become a [`StoredBlock`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlock<Tx>(BlockWithVerifiedHeader<Tx>);

impl<Tx> StoredBlock<Tx> {
    /// Reads the block `id` from `storage`, without verifying it.
    pub(crate) async fn load(storage: &StorageApi<Tx>, id: &HeaderId) -> Option<Self>
    where
        Tx: BinaryDecode<Context = u32> + Hashable<Hash = TxHash> + StorageSize,
    {
        storage
            .get_block(id)
            .await
            .map(|block| Self(BlockWithVerifiedHeader(block)))
    }

    /// Reads the block `id` from `storage`, without verifying it, and returns
    /// the storage error if the read fails.
    pub(crate) async fn try_load(
        storage: &StorageApi<Tx>,
        id: &HeaderId,
    ) -> Result<Option<Self>, DynError>
    where
        Tx: BinaryDecode<Context = u32> + Hashable<Hash = TxHash> + StorageSize,
    {
        Ok(storage
            .try_get_block(id)
            .await?
            .map(|block| Self(BlockWithVerifiedHeader(block))))
    }

    /// Takes `block` as stored without reading it from storage, for tests
    /// that need a [`StoredBlock`] regardless of the storage.
    #[cfg(test)]
    pub(crate) const fn new_unchecked(block: Block<Tx>) -> Self {
        Self(BlockWithVerifiedHeader(block))
    }

    #[must_use]
    pub const fn header(&self) -> &Header {
        self.0.header()
    }

    #[must_use]
    pub const fn uncle_headers(&self) -> &UncleHeaders {
        self.0.uncle_headers()
    }

    pub fn transactions_iter(&self) -> impl ExactSizeIterator<Item = &Tx> + '_ {
        self.0.transactions_iter()
    }

    /// Applies the block on top of its parent state in `ledger`, and returns
    /// the update to commit.
    ///
    /// The stateful checks of every operation run as for any other block.
    /// Only the deferred proofs are not verified again.
    ///
    /// This is the only place that calls
    /// [`PreparedUpdate::trust_batch_proofs`](lb_ledger::PreparedUpdate::trust_batch_proofs),
    /// so that only a block read from storage can skip its deferred proofs.
    pub(crate) fn prepare_update(
        &self,
        ledger: &Ledger<HeaderId>,
    ) -> Result<VerifiedUpdate<HeaderId>, LedgerError<HeaderId>>
    where
        Tx: PreverifiedMantleTransaction + StorageSize + Clone,
    {
        let update = self.0.prepare_update(ledger)?;
        #[expect(
            clippy::disallowed_methods,
            reason = "This node verified the proofs of a stored block before storing it."
        )]
        let update = update.trust_batch_proofs();
        Ok(update)
    }
}

impl<Tx> From<StoredBlock<Tx>> for Block<Tx> {
    fn from(block: StoredBlock<Tx>) -> Self {
        block.0.into()
    }
}
