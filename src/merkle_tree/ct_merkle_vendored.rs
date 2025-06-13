// This file contains code vendored from the ct-merkle library
// Original source: https://github.com/rozbb/ct-merkle
// Original authors: Michael Rosenberg
// License: MIT/Apache-2.0 (dual licensed)
//
// The code in this file is copied from ct-merkle v0.2.0 with minimal modifications.
// Modifications are marked with comments where applicable.

/*
The MIT License (MIT)

Copyright (c) 2022 Michael Rosenberg

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

use digest::Digest;
use std::marker::PhantomData;
use subtle::ConstantTimeEq;

// ============================================================================
// From types.rs
// ============================================================================

/// The root hash of a Merkle tree. This uniquely represents the tree.
#[derive(Clone, Debug)]
pub struct RootHash<H: Digest> {
    /// The root hash of the Merkle tree that this root represents
    pub(crate) root_hash: digest::Output<H>,

    /// The number of leaves in the Merkle tree that this root represents.
    pub(crate) num_leaves: u64,
}

impl<H: Digest> RootHash<H> {
    /// Constructs a `RootHash` from the given hash digest and the number of leaves in the tree
    /// that created it.
    pub fn new(digest: digest::Output<H>, num_leaves: u64) -> RootHash<H> {
        RootHash {
            root_hash: digest,
            num_leaves,
        }
    }

    /// Returns the Merkle Tree Hash of the tree that created this `RootHash`.
    ///
    /// This is precisely the Merkle Tree Hash (MTH) of the tree that created it, as defined in [RFC
    /// 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1).
    pub fn as_bytes(&self) -> &digest::Output<H> {
        &self.root_hash
    }

    /// Returns the number of leaves in the tree that created this `RootHash`.
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }
}

/// Represents a leaf that can be included in a Merkle tree. This only requires that the leaf have a
/// unique hash representation.
pub trait HashableLeaf {
    fn hash<H: digest::Update>(&self, hasher: &mut H);
}

// Blanket hasher impl for anything that resembles a bag of bytes
impl<T: AsRef<[u8]>> HashableLeaf for T {
    fn hash<H: digest::Update>(&self, hasher: &mut H) {
        hasher.update(self.as_ref())
    }
}

// ============================================================================
// From tree_util.rs
// ============================================================================

/// The domain separator used for calculating leaf hashes
const LEAF_HASH_PREFIX: &[u8] = &[0x00];

/// The domain separator used for calculating parent hashes
const PARENT_HASH_PREFIX: &[u8] = &[0x01];

// We make opaque types for leaf and internal node indices so that we don't accidentally confuse
// them in the math

/// An index to a leaf of the tree
// INVARIANT: self.0 <= floor(u64::MAX / 2)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafIdx(u64);

/// An index to an "internal" node of the tree, i.e., a leaf hash or parent node. If there are N
/// leaves, then there are 2*(N - 1) + 1 internal nodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct InternalIdx(u64);

impl LeafIdx {
    /// # Panics
    /// Panics if `idx > ⌊u64::MAX / 2⌋`
    pub(crate) fn new(idx: u64) -> Self {
        assert!(idx <= u64::MAX / 2);
        LeafIdx(idx)
    }
}

impl InternalIdx {
    /// Returns this index as a `u64`
    pub(crate) fn as_u64(&self) -> u64 {
        self.0
    }
}

/// A hasher that prepends the leaf-hash prefix
struct LeafHasher<H: Digest>(H);

impl<H: Digest> LeafHasher<H> {
    fn new() -> Self {
        LeafHasher(H::new_with_prefix(LEAF_HASH_PREFIX))
    }

    fn finalize(self) -> digest::Output<H> {
        self.0.finalize()
    }
}

impl<H: Digest> digest::Update for LeafHasher<H> {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
}

/// Computes the hash of the given leaf's canonical byte representation
pub(crate) fn leaf_hash<H, L>(leaf: &L) -> digest::Output<H>
where
    H: Digest,
    L: HashableLeaf,
{
    let mut hasher = LeafHasher::<H>::new();
    leaf.hash(&mut hasher);
    hasher.finalize()
}

/// Computes the parent of the two given subtrees. This is `H(0x01 || left || right)`.
pub(crate) fn parent_hash<H: Digest>(
    left: &digest::Output<H>,
    right: &digest::Output<H>,
) -> digest::Output<H> {
    let mut hasher = H::new_with_prefix(PARENT_HASH_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

//
// Below is tree math definitions. We use array-based trees, described in
// https://www.rfc-editor.org/rfc/rfc9420.html#name-array-based-trees
//

impl From<LeafIdx> for InternalIdx {
    fn from(leaf: LeafIdx) -> InternalIdx {
        InternalIdx(2 * leaf.0)
    }
}

impl InternalIdx {
    // The level of an internal node is how "odd" it is, i.e., how many trailing ones it has in its
    // binary representation
    pub(crate) fn level(&self) -> u32 {
        self.0.trailing_ones()
    }

    // Returns whether this node is to the left of its parent
    pub(crate) fn is_left(&self, num_leaves: u64) -> bool {
        let p = self.parent(num_leaves);
        self.0 < p.0
    }

    // The rest of the functions are a direct translation of the array-tree math in
    // https://www.ietf.org/archive/id/draft-ietf-mls-protocol-14.html#array-based-trees

    /// Returns the parent of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is the root
    pub(crate) fn parent(&self, num_leaves: u64) -> InternalIdx {
        fn parent_step(idx: InternalIdx) -> InternalIdx {
            let k = idx.level();
            let b = (idx.0 >> (k + 1)) & 0x01;
            InternalIdx((idx.0 | (1 << k)) ^ (b << (k + 1)))
        }

        if *self == root_idx(num_leaves) {
            panic!("root has no parent");
        }

        let mut p = parent_step(*self);
        while p.0 >= num_internal_nodes(num_leaves) {
            p = parent_step(p);
        }

        p
    }

    /// Returns the left child of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is a leaf
    pub(crate) fn left_child(&self) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a leaf");

        InternalIdx(self.0 ^ (0x01 << (k - 1)))
    }

    /// Returns the right child of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is a leaf
    pub(crate) fn right_child(&self, num_leaves: u64) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a leaf");

        let mut r = InternalIdx(self.0 ^ (0x03 << (k - 1)));
        while r.0 >= num_internal_nodes(num_leaves) {
            r = r.left_child();
        }

        r
    }

    /// Returns the sibling of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is the root
    pub(crate) fn sibling(&self, num_leaves: u64) -> InternalIdx {
        let p = self.parent(num_leaves);
        // *_child cannot panic because p is guaranteed to not be a leaf
        if self.0 < p.0 {
            p.right_child(num_leaves)
        } else {
            p.left_child()
        }
    }
}

/// Computes log2(x), with log2(0) := 0
fn log2(x: u64) -> u64 {
    x.checked_ilog2().unwrap_or(0) as u64 // casting u32 -> u64
}

/// The number of internal nodes necessary to represent a tree with `num_leaves` leaves.
///
/// # Panics
/// Panics when `num_leaves > ⌊u64::MAX / 2⌋ + 1`
pub(crate) fn num_internal_nodes(num_leaves: u64) -> u64 {
    if num_leaves == 0 {
        0
    } else {
        2 * (num_leaves - 1) + 1
    }
}

/// Returns the root index of a tree with `num_leaves` leaves
///
/// # Panics
/// Panics when `num_leaves > ⌊u64::MAX / 2⌋ + 1`
pub(crate) fn root_idx(num_leaves: u64) -> InternalIdx {
    let w = num_internal_nodes(num_leaves);
    InternalIdx((1 << log2(w)) - 1)
}

// ============================================================================
// From inclusion.rs
// ============================================================================

/// A proof that a value appears in a Merkle tree
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

impl<H: Digest> InclusionProof<H> {
    /// Returns the byte representation of this inclusion proof.
    ///
    /// This is precisely `PATH(m, D[n])`, described in [RFC 6962
    /// §2.1.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.1), where `n` is the number
    /// of leaves and `m` is the leaf index being proved.
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs an `InclusionProof` from a sequence of digests.
    pub fn from_digests<'a>(digests: impl IntoIterator<Item = &'a digest::Output<H>>) -> Self {
        // The proof is just a concatenation of hashes
        let concatenated_hashes = digests.into_iter().flatten().cloned().collect();

        InclusionProof {
            proof: concatenated_hashes,
            _marker: PhantomData,
        }
    }
}

/// Given a tree size and index, produces a list of tree node indices whose values we need in order
/// to build the inclusion proof.
///
/// This is useful when we don't have the entire tree in memory, e.g., when it is stored on disk or
/// stored in tiles on a remote server. Once the digests are retreived, they can be used in the same
/// order in [`InclusionProof::from_digests`].
///
/// # Panics
/// Panics if `num_leaves == 0`, if `idx >= num_leaves`, or if `idx > ⌊u64::MAX / 2⌋`.
pub fn indices_for_inclusion_proof(num_leaves: u64, idx: u64) -> Vec<u64> {
    if num_leaves == 0 {
        panic!("cannot create an inclusion proof for an empty tree")
    }
    if idx >= num_leaves {
        panic!("cannot create an inclusion proof for an index that's not in the tree")
    }
    if idx > u64::MAX / 2 {
        panic!("leaf index is too high")
    }

    let mut out = Vec::new();
    let root_idx = root_idx(num_leaves);

    // If this is the singleton tree, the proof is empty, and we need no values
    if num_leaves == 1 {
        return out;
    }

    // Start the proof with the sibling hash
    let start_idx = InternalIdx::from(LeafIdx::new(idx));
    let sibling_idx = start_idx.sibling(num_leaves);
    out.push(sibling_idx.as_u64());

    // Collect the hashes of the siblings on the way up the tree
    let mut parent_idx = start_idx.parent(num_leaves);
    while parent_idx != root_idx {
        let sibling_idx = parent_idx.sibling(num_leaves);
        out.push(sibling_idx.as_u64());

        // Go up a level
        parent_idx = parent_idx.parent(num_leaves);
    }

    out
}

// ============================================================================
// From inclusion.rs (verification)
// ============================================================================

impl<H: Digest> InclusionProof<H> {
    /// Verifies that the given `leaf_val` was included in the tree with root `root_hash`.
    ///
    /// This implements verification of `PATH(m, D[n])` as described in [RFC 6962
    /// §2.1.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.1).
    #[allow(dead_code)]
    pub fn verify<L: HashableLeaf>(
        &self,
        leaf_val: &L,
        leaf_idx: u64,
        root_hash: &RootHash<H>,
    ) -> Result<(), &'static str> {
        let num_leaves = root_hash.num_leaves();

        if leaf_idx >= num_leaves {
            return Err("leaf index out of bounds");
        }

        // Empty tree edge case
        if num_leaves == 0 {
            return Err("cannot verify inclusion in empty tree");
        }

        // Check that the proof is the right size
        let expected_proof_size =
            indices_for_inclusion_proof(num_leaves, leaf_idx).len() * <H as Digest>::output_size();
        if self.proof.len() != expected_proof_size {
            return Err("invalid proof length");
        }

        // If the proof is empty (single leaf tree), then the leaf hash is the root hash
        let leaf_hash_value = leaf_hash::<H, _>(leaf_val);
        if self.proof.is_empty() {
            if bool::from(leaf_hash_value.ct_eq(&root_hash.root_hash)) {
                return Ok(());
            } else {
                return Err("root hash mismatch for single leaf");
            }
        }

        // Otherwise, start hashing up the tree
        let mut cur_idx = InternalIdx::from(LeafIdx::new(leaf_idx));
        let mut cur_hash = leaf_hash_value;

        // Process each sibling hash in the proof
        for sibling_hash_bytes in self.proof.chunks(<H as Digest>::output_size()) {
            // Convert sibling hash bytes to proper type
            let sibling_hash = digest::Output::<H>::from_slice(sibling_hash_bytes);

            // Combine with sibling based on position
            cur_hash = if cur_idx.is_left(num_leaves) {
                parent_hash::<H>(&cur_hash, sibling_hash)
            } else {
                parent_hash::<H>(sibling_hash, &cur_hash)
            };

            // Step up the tree
            cur_idx = cur_idx.parent(num_leaves);
        }

        // Verify the computed root matches
        if bool::from(cur_hash.ct_eq(&root_hash.root_hash)) {
            Ok(())
        } else {
            Err("computed root does not match")
        }
    }
}

// ============================================================================
// From consistency.rs (ConsistencyProof struct and verification)
// ============================================================================

/// Given two trees `num_leaves1 > num_leaves2`, finds the lowest node in the rightmost path-to-root
/// of `num_leaves2` whose parent in `num_leaves2` is not the same as the parent in `num_leaves1`.
/// This is guaranteed to exist as long as `num_leaves2` is not a subtree of `num_leaves1`.
///
/// # Panics
/// Panics when `num_leaves1 <= num_leaves2` or `num_leaves2 == 0`. Also panics when `num_leaves2` is
/// a subtree of `num_leaves1`, which occurs when `num_leaves2.is_power_of_two()`. Also panics when
/// `num_leaves1 > ⌊u64::MAX / 2⌋ + 1`.
fn first_node_with_diverging_parents(num_leaves1: u64, num_leaves2: u64) -> InternalIdx {
    assert!(num_leaves1 > num_leaves2);
    assert_ne!(num_leaves2, 0);
    assert!(num_leaves1 <= u64::MAX / 2 + 1);

    let mut idx = InternalIdx::from(LeafIdx::new(num_leaves2 - 1));
    while idx.parent(num_leaves1) == idx.parent(num_leaves2) {
        idx = idx.parent(num_leaves1);
    }

    idx
}

/// A proof that one Merkle tree is a prefix of another. In other words, tree #2 is the result of
/// appending some number of items to the end of tree #1.
#[derive(Clone, Debug)]
pub struct ConsistencyProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

impl<H: Digest> ConsistencyProof<H> {
    /// Returns the byte representation of this consistency proof.
    ///
    /// This is precisely `PROOF(m, D[n])`, described in [RFC 6962
    /// §2.1.2](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.2), where `n` is the number
    /// of leaves and `m` is the leaf index being proved.
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs a `ConsistencyProof` from a sequence of digests.
    // This is identical to `InclusionProof::from_digests`, since proofs are just sequences of
    // digests.
    pub fn from_digests<'a>(digests: impl IntoIterator<Item = &'a digest::Output<H>>) -> Self {
        // The proof is just a concatenation of hashes
        let concatenated_hashes = digests.into_iter().flatten().cloned().collect();

        ConsistencyProof {
            proof: concatenated_hashes,
            _marker: PhantomData,
        }
    }

    /// Verifies that `old_root` is consistent with `new_root`.
    ///
    /// This implements verification of `PROOF(m, D[n])` as described in [RFC 6962
    /// §2.1.2](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.2).
    #[allow(dead_code)]
    pub fn verify(
        &self,
        old_root: &RootHash<H>,
        new_root: &RootHash<H>,
    ) -> Result<(), &'static str> {
        let num_newtree_leaves = new_root.num_leaves();
        let num_oldtree_leaves = old_root.num_leaves();

        if num_oldtree_leaves == 0 {
            return Err("cannot verify consistency from empty tree");
        }
        if num_oldtree_leaves > num_newtree_leaves {
            return Err("old tree size cannot be larger than new tree size");
        }
        if num_newtree_leaves > u64::MAX / 2 + 1 {
            return Err("new tree too big");
        }

        // Check that the proof is the right size
        let num_additions = num_newtree_leaves - num_oldtree_leaves;
        let expected_proof_size = {
            let num_hashes = crate::merkle_tree::consistency::indices_for_consistency_proof(
                num_oldtree_leaves,
                num_additions,
            )
            .len();
            <H as Digest>::output_size() * num_hashes
        };
        if expected_proof_size != self.proof.len() {
            return Err("malformed proof");
        }

        // We have a special case when the old tree is a subtree of the current tree
        let oldtree_is_subtree =
            num_oldtree_leaves.is_power_of_two() || num_oldtree_leaves == num_newtree_leaves;

        // Split the proof into digest-sized chunks
        let mut digests = self
            .proof
            .chunks(<H as Digest>::output_size())
            .map(|chunk| {
                let mut hash = digest::Output::<H>::default();
                hash.copy_from_slice(chunk);
                hash
            });

        // We compute both old and new tree hashes
        let oldtree_root_idx = root_idx(num_oldtree_leaves);
        let (mut running_oldtree_idx, mut running_oldtree_hash) = if oldtree_is_subtree {
            (oldtree_root_idx, old_root.root_hash.clone())
        } else {
            // We can unwrap here because the proof size cannot be 0
            let first_hash = digests.next().unwrap();
            // Our starting point will be a node common to both trees
            let starting_idx =
                first_node_with_diverging_parents(num_newtree_leaves, num_oldtree_leaves);
            (starting_idx, first_hash)
        };
        let mut running_tree_hash = running_oldtree_hash.clone();
        let mut running_newtree_idx = running_oldtree_idx;

        for sibling_hash in digests {
            let sibling_idx = running_newtree_idx.sibling(num_newtree_leaves);

            if running_newtree_idx.is_left(num_newtree_leaves) {
                running_tree_hash = parent_hash::<H>(&running_tree_hash, &sibling_hash);
            } else {
                running_tree_hash = parent_hash::<H>(&sibling_hash, &running_tree_hash);
            }
            // Step up the tree
            running_newtree_idx = running_newtree_idx.parent(num_newtree_leaves);

            // Now do the same with the old tree
            if running_oldtree_idx != oldtree_root_idx
                && sibling_idx == running_oldtree_idx.sibling(num_oldtree_leaves)
            {
                if running_oldtree_idx.is_left(num_oldtree_leaves) {
                    running_oldtree_hash = parent_hash::<H>(&running_oldtree_hash, &sibling_hash);
                } else {
                    running_oldtree_hash = parent_hash::<H>(&sibling_hash, &running_oldtree_hash);
                }
                // Step up the oldtree
                running_oldtree_idx = running_oldtree_idx.parent(num_oldtree_leaves);
            }
        }

        // At the end, the old hash should be the old root, and the new hash should be the new root
        let oldtree_eq = running_oldtree_hash.ct_eq(&old_root.root_hash);
        let tree_eq = running_tree_hash.ct_eq(&new_root.root_hash);
        if !bool::from(oldtree_eq & tree_eq) {
            Err("verification failure")
        } else {
            Ok(())
        }
    }
}
