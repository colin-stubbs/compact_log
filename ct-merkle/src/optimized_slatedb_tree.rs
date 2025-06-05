use crate::{
    consistency::{indices_for_consistency_proof, ConsistencyProof},
    indices_for_inclusion_proof, leaf_hash, parent_hash, root_idx, HashableLeaf, InclusionProof,
    InternalIdx, RootHash,
};
use alloc::{boxed::Box, format, string::String, string::ToString, vec::Vec};
use core::fmt;
use digest::Digest;
use slatedb::{Db, DbReader, WriteBatch};
use std::{sync::Arc, vec};

#[derive(Debug)]
pub enum OptimizedSlateDbTreeError {
    DbError(slatedb::SlateDBError),
    EncodingError(String),
    InconsistentState(String),
}

impl fmt::Display for OptimizedSlateDbTreeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            OptimizedSlateDbTreeError::DbError(e) => write!(f, "SlateDB error: {}", e),
            OptimizedSlateDbTreeError::EncodingError(e) => write!(f, "Encoding error: {}", e),
            OptimizedSlateDbTreeError::InconsistentState(e) => {
                write!(f, "Inconsistent state: {}", e)
            }
        }
    }
}

impl std::error::Error for OptimizedSlateDbTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OptimizedSlateDbTreeError::DbError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<slatedb::SlateDBError> for OptimizedSlateDbTreeError {
    fn from(e: slatedb::SlateDBError) -> Self {
        OptimizedSlateDbTreeError::DbError(e)
    }
}

/// Enum to hold either a read-write Db or a read-only DbReader
pub enum DbHandle {
    ReadWrite(Arc<Db>),
    ReadOnly(Arc<DbReader>),
}

impl DbHandle {
    async fn get(
        &self,
        key: &[u8],
    ) -> Result<Option<slatedb::bytes::Bytes>, slatedb::SlateDBError> {
        match self {
            DbHandle::ReadWrite(db) => db.get(key).await,
            DbHandle::ReadOnly(reader) => reader.get(key).await,
        }
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), OptimizedSlateDbTreeError> {
        match self {
            DbHandle::ReadWrite(db) => db.put(key, value).await.map_err(Into::into),
            DbHandle::ReadOnly(_) => Err(OptimizedSlateDbTreeError::InconsistentState(
                "Cannot write to read-only database".into(),
            )),
        }
    }

    async fn write(&self, batch: WriteBatch) -> Result<(), OptimizedSlateDbTreeError> {
        match self {
            DbHandle::ReadWrite(db) => db.write(batch).await.map_err(Into::into),
            DbHandle::ReadOnly(_) => Err(OptimizedSlateDbTreeError::InconsistentState(
                "Cannot write to read-only database".into(),
            )),
        }
    }
}

/// An optimized SlateDB-backed append-only Merkle tree implementation.
///
/// This implementation minimizes storage by only storing:
/// - Leaf values
/// - Frontier nodes (the minimal set needed to compute any root)
/// - Tree metadata
///
/// Key format: single byte prefix + 8-byte big-endian index
/// - 0x00: metadata (no index)
/// - 0x01: leaf value
/// - 0x02: frontier node hash
pub struct OptimizedSlateDbTree<H, T>
where
    H: Digest + Send + Sync,
    T: HashableLeaf + Send + Sync,
{
    db: DbHandle,
    _phantom_h: core::marker::PhantomData<H>,
    _phantom_t: core::marker::PhantomData<T>,
}

const META_PREFIX: u8 = 0x00;
const LEAF_PREFIX: u8 = 0x01;
const FRONTIER_PREFIX: u8 = 0x02;
const META_KEY: &[u8] = &[META_PREFIX];

impl<H, T> OptimizedSlateDbTree<H, T>
where
    H: Digest + Send + Sync,
    T: HashableLeaf + serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
{
    pub async fn new(db: Arc<Db>) -> Result<Self, OptimizedSlateDbTreeError> {
        let tree = Self {
            db: DbHandle::ReadWrite(db),
            _phantom_h: core::marker::PhantomData,
            _phantom_t: core::marker::PhantomData,
        };

        let existing_leaves = tree.get_num_leaves().await?;

        if existing_leaves.is_none() {
            tree.set_num_leaves(0).await?;
        }

        Ok(tree)
    }

    pub async fn from_reader(reader: Arc<DbReader>) -> Result<Self, OptimizedSlateDbTreeError> {
        let tree = Self {
            db: DbHandle::ReadOnly(reader),
            _phantom_h: core::marker::PhantomData,
            _phantom_t: core::marker::PhantomData,
        };

        Ok(tree)
    }

    fn make_key(prefix: u8, index: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(9);
        key.push(prefix);
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    fn leaf_key(index: u64) -> Vec<u8> {
        Self::make_key(LEAF_PREFIX, index)
    }

    fn frontier_key(index: u64) -> Vec<u8> {
        Self::make_key(FRONTIER_PREFIX, index)
    }

    async fn get_num_leaves(&self) -> Result<Option<u64>, OptimizedSlateDbTreeError> {
        match self.db.get(META_KEY).await? {
            Some(bytes) => {
                let bytes_ref: &[u8] = bytes.as_ref();
                let bytes_array: [u8; 8] = bytes_ref.try_into().map_err(|_| {
                    OptimizedSlateDbTreeError::EncodingError("Invalid metadata".into())
                })?;
                let num_leaves = u64::from_be_bytes(bytes_array);
                Ok(Some(num_leaves))
            }
            None => Ok(None),
        }
    }

    async fn set_num_leaves(&self, num_leaves: u64) -> Result<(), OptimizedSlateDbTreeError> {
        self.db.put(META_KEY, &num_leaves.to_be_bytes()).await
    }

    pub async fn len(&self) -> Result<u64, OptimizedSlateDbTreeError> {
        Ok(self.get_num_leaves().await?.unwrap_or(0))
    }

    pub async fn is_empty(&self) -> Result<bool, OptimizedSlateDbTreeError> {
        Ok(self.len().await? == 0)
    }

    /// Computes which frontier nodes need to be stored for a given tree size
    fn frontier_indices(num_leaves: u64) -> Vec<InternalIdx> {
        if num_leaves == 0 {
            return vec![];
        }

        let mut indices = vec![];
        let mut remaining = num_leaves;
        let mut offset = 0u64;

        // Decompose the tree size into powers of 2
        while remaining > 0 {
            let subtree_size = 1u64 << (63 - remaining.leading_zeros());
            if subtree_size <= remaining {
                // The root of this complete subtree is a frontier node
                let subtree_root = root_idx(subtree_size);
                // Adjust for the offset in the overall tree
                let adjusted_idx = InternalIdx::new(subtree_root.as_u64() + 2 * offset);
                indices.push(adjusted_idx);

                offset += subtree_size;
                remaining -= subtree_size;
            } else {
                remaining = 0;
            }
        }

        indices
    }

    /// Computes a node hash, either from storage or by computing from children
    fn get_or_compute_hash(
        &self,
        idx: InternalIdx,
        num_leaves: u64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<digest::Output<H>, OptimizedSlateDbTreeError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // Check if this is a frontier node
            if let Some(bytes) = self.db.get(&Self::frontier_key(idx.as_u64())).await? {
                let mut hash = digest::Output::<H>::default();
                if bytes.len() == hash.len() {
                    hash.copy_from_slice(&bytes);
                    return Ok(hash);
                } else {
                    return Err(OptimizedSlateDbTreeError::EncodingError(
                        "Invalid hash size".into(),
                    ));
                }
            }

            // If it's a leaf node, compute from the leaf value
            if idx.level() == 0 {
                let leaf_idx = idx.as_u64() / 2;
                if let Some(bytes) = self.db.get(&Self::leaf_key(leaf_idx)).await? {
                    let leaf: T = bincode::deserialize(&bytes)
                        .map_err(|e| OptimizedSlateDbTreeError::EncodingError(e.to_string()))?;
                    return Ok(leaf_hash::<H, _>(&leaf));
                } else {
                    // Empty node
                    return Ok(digest::Output::<H>::default());
                }
            }

            // Otherwise, compute from children
            let left_child = idx.left_child();
            let right_child = idx.right_child(num_leaves);

            let left_hash = self.get_or_compute_hash(left_child, num_leaves).await?;
            let right_hash = self.get_or_compute_hash(right_child, num_leaves).await?;

            Ok(parent_hash::<H>(&left_hash, &right_hash))
        })
    }

    /// Appends the given item to the end of the list.
    pub async fn push(&mut self, new_val: T) -> Result<(), OptimizedSlateDbTreeError> {
        let num_leaves = self.len().await?;

        if num_leaves >= u64::MAX / 2 {
            return Err(OptimizedSlateDbTreeError::InconsistentState(
                "Tree is full".into(),
            ));
        }

        let mut batch = WriteBatch::new();

        // Store the leaf value
        let leaf_bytes = bincode::serialize(&new_val)
            .map_err(|e| OptimizedSlateDbTreeError::EncodingError(e.to_string()))?;
        batch.put(&Self::leaf_key(num_leaves), &leaf_bytes);

        // Update frontier nodes
        let new_num_leaves = num_leaves + 1;

        // Remove old frontier nodes that are no longer needed
        let old_frontier = Self::frontier_indices(num_leaves);
        let new_frontier = Self::frontier_indices(new_num_leaves);

        // Find nodes to remove (in old but not in new)
        for old_idx in &old_frontier {
            if !new_frontier
                .iter()
                .any(|new_idx| new_idx.as_u64() == old_idx.as_u64())
            {
                batch.delete(&Self::frontier_key(old_idx.as_u64()));
            }
        }

        // Compute and store new frontier nodes
        for frontier_idx in &new_frontier {
            // Only compute if it's not already stored
            if !old_frontier
                .iter()
                .any(|old_idx| old_idx.as_u64() == frontier_idx.as_u64())
            {
                let hash = self
                    .compute_subtree_hash(*frontier_idx, new_num_leaves, &new_val, num_leaves)
                    .await?;
                batch.put(&Self::frontier_key(frontier_idx.as_u64()), hash.as_ref());
            }
        }

        // Update metadata
        batch.put(META_KEY, &new_num_leaves.to_be_bytes());

        self.db.write(batch).await?;

        Ok(())
    }

    /// Computes the hash of a subtree, using the new leaf if applicable
    fn compute_subtree_hash<'a>(
        &'a self,
        idx: InternalIdx,
        num_leaves: u64,
        new_leaf: &'a T,
        old_num_leaves: u64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<digest::Output<H>, OptimizedSlateDbTreeError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            // If this is the new leaf, compute its hash
            if idx.level() == 0 && idx.as_u64() / 2 == old_num_leaves {
                return Ok(leaf_hash::<H, _>(new_leaf));
            }

            // If it's a leaf node, get from storage
            if idx.level() == 0 {
                let leaf_idx = idx.as_u64() / 2;
                if let Some(bytes) = self.db.get(&Self::leaf_key(leaf_idx)).await? {
                    let leaf: T = bincode::deserialize(&bytes)
                        .map_err(|e| OptimizedSlateDbTreeError::EncodingError(e.to_string()))?;
                    return Ok(leaf_hash::<H, _>(&leaf));
                } else {
                    return Ok(digest::Output::<H>::default());
                }
            }

            // Otherwise, compute from children
            let left_child = idx.left_child();
            let right_child = idx.right_child(num_leaves);

            let left_hash = if left_child.as_u64() / 2 < old_num_leaves {
                self.get_or_compute_hash(left_child, old_num_leaves).await?
            } else {
                self.compute_subtree_hash(left_child, num_leaves, new_leaf, old_num_leaves)
                    .await?
            };

            let right_hash = if right_child.as_u64() / 2 < old_num_leaves {
                self.get_or_compute_hash(right_child, old_num_leaves)
                    .await?
            } else {
                self.compute_subtree_hash(right_child, num_leaves, new_leaf, old_num_leaves)
                    .await?
            };

            Ok(parent_hash::<H>(&left_hash, &right_hash))
        })
    }

    /// Appends multiple items to the tree in a single atomic batch operation.
    pub async fn batch_push(&mut self, items: Vec<T>) -> Result<u64, OptimizedSlateDbTreeError> {
        self.batch_push_with_data(items, alloc::vec![]).await
    }

    /// Appends multiple items to the tree along with additional key-value pairs in a single atomic batch.
    pub async fn batch_push_with_data(
        &self,
        items: Vec<T>,
        additional_data: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<u64, OptimizedSlateDbTreeError> {
        let starting_index = self.len().await?;

        if items.is_empty() && additional_data.is_empty() {
            return Ok(starting_index);
        }

        let mut batch = WriteBatch::new();

        // Store all leaf values
        for (i, item) in items.iter().enumerate() {
            let leaf_bytes = bincode::serialize(item)
                .map_err(|e| OptimizedSlateDbTreeError::EncodingError(e.to_string()))?;
            batch.put(&Self::leaf_key(starting_index + i as u64), &leaf_bytes);
        }

        // Remove old frontier nodes
        let old_frontier = Self::frontier_indices(starting_index);
        for idx in &old_frontier {
            batch.delete(&Self::frontier_key(idx.as_u64()));
        }

        // Compute and store new frontier nodes
        let new_num_leaves = starting_index + items.len() as u64;
        let new_frontier = Self::frontier_indices(new_num_leaves);

        for frontier_idx in &new_frontier {
            let hash = self
                .compute_batch_subtree_hash(*frontier_idx, new_num_leaves, &items, starting_index)
                .await?;
            batch.put(&Self::frontier_key(frontier_idx.as_u64()), hash.as_ref());
        }

        // Update metadata
        batch.put(META_KEY, &new_num_leaves.to_be_bytes());

        // Add additional key-value pairs
        for (key, value) in additional_data {
            batch.put(&key, &value);
        }

        self.db.write(batch).await?;

        Ok(starting_index)
    }

    /// Computes hash for batch operations
    fn compute_batch_subtree_hash<'a>(
        &'a self,
        idx: InternalIdx,
        num_leaves: u64,
        new_items: &'a [T],
        starting_index: u64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<digest::Output<H>, OptimizedSlateDbTreeError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            // If this is a leaf node
            if idx.level() == 0 {
                let leaf_idx = idx.as_u64() / 2;

                // Check if it's one of the new leaves
                if leaf_idx >= starting_index && leaf_idx < starting_index + new_items.len() as u64
                {
                    let item_idx = (leaf_idx - starting_index) as usize;
                    return Ok(leaf_hash::<H, _>(&new_items[item_idx]));
                }

                // Otherwise get from storage
                if let Some(bytes) = self.db.get(&Self::leaf_key(leaf_idx)).await? {
                    let leaf: T = bincode::deserialize(&bytes)
                        .map_err(|e| OptimizedSlateDbTreeError::EncodingError(e.to_string()))?;
                    return Ok(leaf_hash::<H, _>(&leaf));
                } else {
                    return Ok(digest::Output::<H>::default());
                }
            }

            // Otherwise, compute from children
            let left_child = idx.left_child();
            let right_child = idx.right_child(num_leaves);

            let left_hash = self
                .compute_batch_subtree_hash(left_child, num_leaves, new_items, starting_index)
                .await?;
            let right_hash = self
                .compute_batch_subtree_hash(right_child, num_leaves, new_items, starting_index)
                .await?;

            Ok(parent_hash::<H>(&left_hash, &right_hash))
        })
    }

    /// Returns the root hash of this tree.
    pub async fn root(&self) -> Result<RootHash<H>, OptimizedSlateDbTreeError> {
        let num_leaves = self.len().await?;

        let root_hash = if num_leaves == 0 {
            H::digest(b"")
        } else {
            let root_idx = root_idx(num_leaves);
            self.get_or_compute_hash(root_idx, num_leaves).await?
        };

        Ok(RootHash::new(root_hash, num_leaves))
    }

    pub async fn get(&self, idx: u64) -> Result<Option<T>, OptimizedSlateDbTreeError> {
        match self.db.get(&Self::leaf_key(idx)).await? {
            Some(bytes) => {
                let leaf = bincode::deserialize(&bytes)
                    .map_err(|e| OptimizedSlateDbTreeError::EncodingError(e.to_string()))?;
                Ok(Some(leaf))
            }
            None => Ok(None),
        }
    }

    /// Returns a proof of inclusion of the item at the given index.
    pub async fn prove_inclusion(
        &self,
        idx: u64,
    ) -> Result<InclusionProof<H>, OptimizedSlateDbTreeError> {
        let num_leaves = self.len().await?;

        if idx >= num_leaves {
            return Err(OptimizedSlateDbTreeError::InconsistentState(format!(
                "Index {} out of bounds (tree has {} leaves)",
                idx, num_leaves
            )));
        }

        let idxs = indices_for_inclusion_proof(num_leaves, idx);

        let mut sibling_hashes = Vec::with_capacity(idxs.len());
        for &node_idx in &idxs {
            let hash = self
                .get_or_compute_hash(InternalIdx::new(node_idx), num_leaves)
                .await?;
            sibling_hashes.push(hash);
        }

        Ok(InclusionProof::from_digests(sibling_hashes.iter()))
    }

    /// Produces a proof that a tree with `old_size` leaves is a prefix of this tree.
    pub async fn prove_consistency(
        &self,
        old_size: u64,
    ) -> Result<ConsistencyProof<H>, OptimizedSlateDbTreeError> {
        let new_size = self.len().await?;

        if old_size == 0 {
            return Err(OptimizedSlateDbTreeError::InconsistentState(
                "Cannot create consistency proof from empty tree".into(),
            ));
        }

        if old_size >= new_size {
            return Err(OptimizedSlateDbTreeError::InconsistentState(format!(
                "Old size {} must be less than current size {}",
                old_size, new_size
            )));
        }

        let num_additions = new_size - old_size;

        let idxs = indices_for_consistency_proof(old_size, num_additions);

        let mut proof_hashes = Vec::with_capacity(idxs.len());
        for &node_idx in &idxs {
            let hash = self
                .get_or_compute_hash(InternalIdx::new(node_idx), new_size)
                .await?;
            proof_hashes.push(hash);
        }

        Ok(ConsistencyProof::from_digests(proof_hashes.iter()))
    }

    pub async fn prove_consistency_between(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof<H>, OptimizedSlateDbTreeError> {
        if old_size == 0 {
            return Err(OptimizedSlateDbTreeError::InconsistentState(
                "Cannot create consistency proof from empty tree".into(),
            ));
        }

        if old_size > new_size {
            return Err(OptimizedSlateDbTreeError::InconsistentState(format!(
                "Old size {} must be less than or equal to new size {}",
                old_size, new_size
            )));
        }

        if old_size == new_size {
            return Ok(ConsistencyProof::from_digests(std::iter::empty()));
        }

        let current_size = self.len().await?;
        if new_size > current_size {
            return Err(OptimizedSlateDbTreeError::InconsistentState(format!(
                "New size {} exceeds current tree size {}",
                new_size, current_size
            )));
        }

        let idxs = indices_for_consistency_proof(old_size, new_size - old_size);

        let mut proof_hashes = Vec::with_capacity(idxs.len());
        for &node_idx in &idxs {
            let hash = self
                .get_or_compute_hash(InternalIdx::new(node_idx), new_size)
                .await?;
            proof_hashes.push(hash);
        }

        Ok(ConsistencyProof::from_digests(proof_hashes.iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem_backed_tree::MemoryBackedTree;
    use alloc::vec;
    use sha2::Sha256;
    use slatedb::config::DbOptions;

    type TestTree = OptimizedSlateDbTree<Sha256, Vec<u8>>;
    type MemTree = MemoryBackedTree<Sha256, Vec<u8>>;

    #[test]
    fn test_frontier_indices() {
        // Tree with 1 leaf: frontier is just the leaf
        let frontier = OptimizedSlateDbTree::<Sha256, Vec<u8>>::frontier_indices(1);
        assert_eq!(frontier.len(), 1);
        assert_eq!(frontier[0].as_u64(), 0); // Root of single-node tree

        // Tree with 2 leaves: frontier is the root
        let frontier = OptimizedSlateDbTree::<Sha256, Vec<u8>>::frontier_indices(2);
        assert_eq!(frontier.len(), 1);
        assert_eq!(frontier[0].as_u64(), 1); // Root of 2-node tree

        // Tree with 3 leaves: frontier is root of first 2 + leaf 3
        let frontier = OptimizedSlateDbTree::<Sha256, Vec<u8>>::frontier_indices(3);
        assert_eq!(frontier.len(), 2);
        assert_eq!(frontier[0].as_u64(), 1); // Root of first subtree (2 leaves)
        assert_eq!(frontier[1].as_u64(), 4); // Third leaf

        // Tree with 4 leaves: frontier is just the root
        let frontier = OptimizedSlateDbTree::<Sha256, Vec<u8>>::frontier_indices(4);
        assert_eq!(frontier.len(), 1);
        assert_eq!(frontier[0].as_u64(), 3); // Root of 4-node tree

        // Tree with 5 leaves: frontier is root of first 4 + leaf 5
        let frontier = OptimizedSlateDbTree::<Sha256, Vec<u8>>::frontier_indices(5);
        assert_eq!(frontier.len(), 2);
        assert_eq!(frontier[0].as_u64(), 3); // Root of first subtree (4 leaves)
        assert_eq!(frontier[1].as_u64(), 8); // Fifth leaf

        // Tree with 7 leaves: 4 + 2 + 1
        let frontier = OptimizedSlateDbTree::<Sha256, Vec<u8>>::frontier_indices(7);
        assert_eq!(frontier.len(), 3);
        assert_eq!(frontier[0].as_u64(), 3); // Root of first 4
        assert_eq!(frontier[1].as_u64(), 9); // Root of next 2
        assert_eq!(frontier[2].as_u64(), 12); // Last leaf
    }

    #[tokio::test]
    async fn test_basic_operations() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_opt_tree", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut tree = TestTree::new(db).await.unwrap();

        assert!(tree.is_empty().await.unwrap());
        assert_eq!(tree.len().await.unwrap(), 0);

        tree.push(vec![1, 2, 3]).await.unwrap();
        tree.push(vec![4, 5, 6]).await.unwrap();
        tree.push(vec![7, 8, 9]).await.unwrap();

        assert_eq!(tree.len().await.unwrap(), 3);
        assert!(!tree.is_empty().await.unwrap());

        assert_eq!(tree.get(0).await.unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(tree.get(1).await.unwrap(), Some(vec![4, 5, 6]));
        assert_eq!(tree.get(2).await.unwrap(), Some(vec![7, 8, 9]));
        assert_eq!(tree.get(3).await.unwrap(), None);

        let root1 = tree.root().await.unwrap();
        tree.push(vec![10, 11, 12]).await.unwrap();
        let root2 = tree.root().await.unwrap();

        assert_ne!(root1.as_bytes(), root2.as_bytes());
        assert_eq!(root1.num_leaves(), 3);
        assert_eq!(root2.num_leaves(), 4);
    }

    #[tokio::test]
    async fn test_matches_memory_backed_tree() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_opt_tree2", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut opt_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        assert_eq!(
            opt_tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Empty trees should have same root"
        );

        let test_values = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
            vec![13, 14, 15],
            vec![16, 17, 18],
            vec![19, 20, 21],
            vec![22, 23, 24],
        ];

        for (i, value) in test_values.iter().enumerate() {
            opt_tree.push(value.clone()).await.unwrap();
            mem_tree.push(value.clone());

            let opt_root = opt_tree.root().await.unwrap();
            let mem_root = mem_tree.root();

            assert_eq!(
                opt_root.as_bytes(),
                mem_root.as_bytes(),
                "Roots should match after {} additions",
                i + 1
            );
            assert_eq!(
                opt_root.num_leaves(),
                mem_root.num_leaves(),
                "Leaf counts should match after {} additions",
                i + 1
            );
        }
    }

    #[tokio::test]
    async fn test_inclusion_proofs() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts(
                "/tmp/test_opt_inclusion",
                DbOptions::default(),
                object_store,
            )
            .await
            .unwrap(),
        );

        let mut opt_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        for i in 0..20u8 {
            opt_tree.push(vec![i]).await.unwrap();
            mem_tree.push(vec![i]);
        }

        let opt_root = opt_tree.root().await.unwrap();
        let mem_root = mem_tree.root();

        // Test inclusion proofs for all indices
        for idx in 0..20 {
            let opt_proof = opt_tree.prove_inclusion(idx).await.unwrap();
            let mem_proof = mem_tree.prove_inclusion(idx as usize);

            assert_eq!(
                opt_proof.as_bytes(),
                mem_proof.as_bytes(),
                "Inclusion proofs should match for index {}",
                idx
            );

            let leaf = vec![idx as u8];
            assert!(
                opt_root.verify_inclusion(&leaf, idx, &opt_proof).is_ok(),
                "Optimized proof should verify for index {}",
                idx
            );
            assert!(
                mem_root.verify_inclusion(&leaf, idx, &mem_proof).is_ok(),
                "Memory proof should verify for index {}",
                idx
            );
        }
    }

    #[tokio::test]
    async fn test_consistency_proofs() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts(
                "/tmp/test_opt_consistency",
                DbOptions::default(),
                object_store,
            )
            .await
            .unwrap(),
        );

        let mut opt_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        // Add initial items
        for i in 0..10u8 {
            opt_tree.push(vec![i]).await.unwrap();
            mem_tree.push(vec![i]);
        }

        let old_opt_root = opt_tree.root().await.unwrap();
        let old_mem_root = mem_tree.root();

        // Add more items
        for i in 10..20u8 {
            opt_tree.push(vec![i]).await.unwrap();
            mem_tree.push(vec![i]);
        }

        let new_opt_root = opt_tree.root().await.unwrap();
        let new_mem_root = mem_tree.root();

        // Test consistency proof
        let opt_proof = opt_tree.prove_consistency(10).await.unwrap();
        let mem_proof = mem_tree.prove_consistency(10);

        assert_eq!(
            opt_proof.as_bytes(),
            mem_proof.as_bytes(),
            "Consistency proofs should match"
        );

        assert!(
            new_opt_root
                .verify_consistency(&old_opt_root, &opt_proof)
                .is_ok(),
            "Optimized consistency proof should verify"
        );
        assert!(
            new_mem_root
                .verify_consistency(&old_mem_root, &mem_proof)
                .is_ok(),
            "Memory consistency proof should verify"
        );
    }

    #[tokio::test]
    async fn test_batch_push() {
        let object_store = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = Arc::new(
            Db::open_with_opts("/tmp/test_opt_batch", DbOptions::default(), object_store)
                .await
                .unwrap(),
        );

        let mut opt_tree = TestTree::new(db).await.unwrap();
        let mut mem_tree = MemTree::new();

        let items = vec![vec![1], vec![2], vec![3], vec![4], vec![5]];
        opt_tree.batch_push(items.clone()).await.unwrap();

        for item in items {
            mem_tree.push(item);
        }

        assert_eq!(opt_tree.len().await.unwrap(), 5);
        assert_eq!(
            opt_tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Roots should match after batch push"
        );

        // Test with more items
        let more_items = vec![vec![6], vec![7], vec![8], vec![9], vec![10]];
        opt_tree.batch_push(more_items.clone()).await.unwrap();

        for item in more_items {
            mem_tree.push(item);
        }

        assert_eq!(opt_tree.len().await.unwrap(), 10);
        assert_eq!(
            opt_tree.root().await.unwrap().as_bytes(),
            mem_tree.root().as_bytes(),
            "Roots should match after second batch"
        );
    }
}
