use crate::types::{CtError, Result};
use ct_merkle::{
    slatedb_backed_tree::SlateDbBackedTree, ConsistencyProof, InclusionProof, RootHash,
};
use sha2::Sha256;
use slatedb::Db;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Certificate {
    pub data: Vec<u8>, // MerkleTreeLeaf data, not raw certificate
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.data // This returns the MerkleTreeLeaf bytes that ct-merkle will hash
    }
}

impl serde::Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.data.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Certificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = Vec::<u8>::deserialize(deserializer)?;
        Ok(Certificate { data })
    }
}

/// Storage-backed Merkle tree using ct-merkle's SlateDbBackedTree
pub struct StorageBackedMerkleTree {
    tree: tokio::sync::RwLock<SlateDbBackedTree<Sha256, Certificate>>,
}

impl StorageBackedMerkleTree {
    pub async fn new(db: Arc<Db>) -> Result<Self> {
        let tree = SlateDbBackedTree::new(db).await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to create SlateDbBackedTree: {:?}",
                e
            )))
        })?;

        Ok(Self {
            tree: tokio::sync::RwLock::new(tree),
        })
    }

    pub async fn from_checkpoint(
        path: slatedb::object_store::path::Path,
        object_store: Arc<dyn slatedb::object_store::ObjectStore>,
        checkpoint_id: uuid::Uuid,
    ) -> Result<Self> {
        use slatedb::{config::DbReaderOptions, DbReader};

        let reader = DbReader::open(
            path,
            object_store,
            Some(checkpoint_id),
            DbReaderOptions::default(),
        )
        .await
        .map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to open checkpoint reader: {:?}",
                e
            )))
        })?;

        let tree = SlateDbBackedTree::from_reader(Arc::new(reader)).await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to create SlateDbBackedTree from reader: {:?}",
                e
            )))
        })?;

        Ok(Self {
            tree: tokio::sync::RwLock::new(tree),
        })
    }

    pub async fn size(&self) -> Result<u64> {
        let tree = self.tree.read().await;
        tree.len().await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to get tree size: {:?}",
                e
            )))
        })
    }

    pub async fn batch_push_with_data(
        &self,
        cert_data_vec: Vec<Vec<u8>>,
        additional_data: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<u64> {
        let mut tree = self.tree.write().await;
        let certificates: Vec<Certificate> = cert_data_vec
            .into_iter()
            .map(|data| Certificate { data })
            .collect();
        tree.batch_push_with_data(certificates, additional_data)
            .await
            .map_err(|e| {
                CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                    "Failed to batch push with data: {:?}",
                    e
                )))
            })
    }

    pub async fn root(&self) -> Result<RootHash<Sha256>> {
        let tree = self.tree.read().await;
        tree.root().await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to get root: {:?}",
                e
            )))
        })
    }

    pub async fn prove_inclusion_efficient(
        &self,
        tree_size: u64,
        leaf_index: u64,
    ) -> Result<InclusionProof<Sha256>> {
        if leaf_index >= tree_size {
            return Err(CtError::BadRequest(
                "Leaf index out of bounds for requested tree size".into(),
            ));
        }

        // Check if requested tree size is valid (not larger than current tree)
        let current_tree_size = self.size().await?;
        if tree_size > current_tree_size {
            return Err(CtError::BadRequest(format!(
                "Requested tree size {} exceeds current tree size {}",
                tree_size, current_tree_size
            )));
        }

        let tree = self.tree.read().await;
        let proof = (*tree).prove_inclusion(leaf_index).await.map_err(|e| {
            CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                "Failed to prove inclusion: {:?}",
                e
            )))
        })?;

        Ok(proof)
    }

    pub async fn consistency_proof_between_sizes(
        &self,
        old_tree_size: u64,
        new_tree_size: u64,
    ) -> Result<ConsistencyProof<Sha256>> {
        if old_tree_size > new_tree_size {
            return Err(CtError::BadRequest(
                "Old tree size cannot be larger than new tree size".into(),
            ));
        }

        if old_tree_size == new_tree_size {
            return Ok(ConsistencyProof::from_digests(std::iter::empty()));
        }

        if old_tree_size == 0 {
            return Err(CtError::BadRequest(
                "Cannot produce consistency proof starting from empty tree".into(),
            ));
        }

        let current_tree_size = self.size().await?;
        if old_tree_size > current_tree_size {
            return Err(CtError::BadRequest(format!(
                "Old tree size {} exceeds current tree size {}",
                old_tree_size, current_tree_size
            )));
        }
        if new_tree_size > current_tree_size {
            return Err(CtError::BadRequest(format!(
                "New tree size {} exceeds current tree size {}",
                new_tree_size, current_tree_size
            )));
        }

        let tree = self.tree.read().await;
        let proof = (*tree)
            .prove_consistency(old_tree_size)
            .await
            .map_err(|e| {
                CtError::Storage(crate::storage::StorageError::InvalidFormat(format!(
                    "Failed to prove consistency: {:?}",
                    e
                )))
            })?;

        Ok(proof)
    }
}

pub mod serialization {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    pub fn inclusion_proof_to_audit_path(proof: &InclusionProof<Sha256>) -> Vec<String> {
        // Get the raw proof bytes
        let proof_bytes = proof.as_bytes();

        // Each hash in the proof is 32 bytes (SHA256 output size)
        const HASH_SIZE: usize = 32;

        // Split the proof bytes into individual hashes and encode each as base64
        proof_bytes
            .chunks(HASH_SIZE)
            .map(|hash_bytes| BASE64.encode(hash_bytes))
            .collect()
    }

    pub fn consistency_proof_to_path(proof: &ConsistencyProof<Sha256>) -> Vec<String> {
        // Get the raw proof bytes
        let proof_bytes = proof.as_bytes();

        // Each hash in the proof is 32 bytes (SHA256 output size)
        const HASH_SIZE: usize = 32;

        // Split the proof bytes into individual hashes and encode each as base64
        proof_bytes
            .chunks(HASH_SIZE)
            .map(|hash_bytes| BASE64.encode(hash_bytes))
            .collect()
    }
}
