use crate::merkle_tree::ct_merkle_vendored::{root_idx, InternalIdx, LeafIdx};

/// Given a tree size and number of additions, produces a list of tree node indices whose values in
/// the new tree (i.e., including the additions) are needed to build the consistency proof.
///
/// # Panics
/// Panics if `num_oldtree_leaves == 0` or `num_oldtree_leaves + num_additions > ⌊u64::MAX / 2⌋ + 1`.
pub fn indices_for_consistency_proof(num_oldtree_leaves: u64, num_additions: u64) -> Vec<u64> {
    if num_oldtree_leaves == 0 {
        panic!("cannot produce a consistency proof starting from an empty tree");
    }
    if num_oldtree_leaves
        .checked_add(num_additions)
        .is_some_and(|s| s > u64::MAX / 2 + 1)
    {
        panic!("too many leaves")
    }

    let num_newtree_leaves = num_oldtree_leaves + num_additions;

    if num_oldtree_leaves == num_newtree_leaves {
        return Vec::new();
    }

    subproof(num_oldtree_leaves, num_newtree_leaves, true)
}

/// RFC 6962 SUBPROOF algorithm
pub(crate) fn subproof(m: u64, n: u64, b: bool) -> Vec<u64> {
    if m == n {
        return if b {
            vec![]
        } else {
            vec![root_idx(m).as_u64()]
        };
    }

    let k = largest_power_of_two_less_than(n);

    if m <= k {
        // SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
        let mut result = subproof(m, k, b);

        // Add MTH(D[k:n]) - the root of the right subtree
        let subtree_root = compute_subtree_root(k, n);
        result.push(subtree_root.as_u64());

        result
    } else {
        // SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
        let mut result = subproof(m - k, n - k, false);
        result.push(root_idx(k).as_u64());
        result
    }
}

/// Compute the root of a subtree containing leaves [start, end)
pub(crate) fn compute_subtree_root(start: u64, end: u64) -> InternalIdx {
    let size = end - start;

    if size == 1 {
        // Single leaf
        return LeafIdx::new(start).into();
    }

    // For multiple leaves, recursively compute the root
    let k = largest_power_of_two_less_than(size);

    let left_root = compute_subtree_root(start, start + k);
    let right_root = compute_subtree_root(start + k, end);

    // Verify that left and right are siblings, then return their parent
    // In a properly constructed tree, the sibling of left_root should be right_root
    debug_assert_eq!(
        left_root.sibling(end),
        right_root,
        "Left and right roots should be siblings"
    );

    // Return the parent of these two nodes
    left_root.parent(end)
}

pub(crate) fn largest_power_of_two_less_than(n: u64) -> u64 {
    if n <= 1 {
        panic!("No power of two less than {}", n);
    }

    // Find the largest power of 2 that is strictly less than n
    let mut power = 1u64;
    while power * 2 < n {
        power *= 2;
    }
    power
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_tree::ct_merkle_vendored::{root_idx, LeafIdx};

    #[test]
    fn test_indices_for_consistency_proof_same_size() {
        // Same size should return empty proof
        let indices = indices_for_consistency_proof(5, 0);
        assert!(indices.is_empty());
    }

    #[test]
    fn test_indices_for_consistency_proof_power_of_two() {
        // When old_size is a power of 2
        let indices = indices_for_consistency_proof(4, 3);
        assert!(!indices.is_empty());

        let indices = indices_for_consistency_proof(8, 8);
        assert!(!indices.is_empty());
    }

    #[test]
    #[should_panic(expected = "cannot produce a consistency proof starting from an empty tree")]
    fn test_indices_for_consistency_proof_empty_tree() {
        indices_for_consistency_proof(0, 5);
    }

    #[test]
    fn test_largest_power_of_two_less_than() {
        assert_eq!(largest_power_of_two_less_than(2), 1);
        assert_eq!(largest_power_of_two_less_than(3), 2);
        assert_eq!(largest_power_of_two_less_than(4), 2);
        assert_eq!(largest_power_of_two_less_than(5), 4);
        assert_eq!(largest_power_of_two_less_than(7), 4);
        assert_eq!(largest_power_of_two_less_than(8), 4);
        assert_eq!(largest_power_of_two_less_than(9), 8);
    }

    #[test]
    #[should_panic(expected = "No power of two less than 1")]
    fn test_largest_power_of_two_less_than_one() {
        largest_power_of_two_less_than(1);
    }

    #[test]
    #[should_panic(expected = "No power of two less than 0")]
    fn test_largest_power_of_two_less_than_zero() {
        largest_power_of_two_less_than(0);
    }

    #[test]
    fn test_subproof_base_cases() {
        // Test m == n with b = true (should return empty)
        let result = subproof(5, 5, true);
        assert!(result.is_empty());

        // Test m == n with b = false (should return root)
        let result = subproof(5, 5, false);
        assert_eq!(result, vec![root_idx(5).as_u64()]);
    }

    #[test]
    fn test_subproof_left_subtree() {
        // When m <= k (left subtree case)
        // For n=7, k=4, so testing with m=3
        let result = subproof(3, 7, true);
        // Should get SUBPROOF(3, 4, true) : MTH(D[4:7])
        assert!(!result.is_empty());
        assert!(result.contains(&compute_subtree_root(4, 7).as_u64()));
    }

    #[test]
    fn test_subproof_right_subtree() {
        // When m > k (right subtree case)
        // For n=7, k=4, so testing with m=5
        let result = subproof(5, 7, false);
        // Should get SUBPROOF(1, 3, false) : MTH(D[0:4])
        assert!(!result.is_empty());
        assert!(result.contains(&root_idx(4).as_u64()));
    }

    #[test]
    fn test_compute_subtree_root_single_leaf() {
        // Single leaf case
        let root = compute_subtree_root(5, 6);
        assert_eq!(root, LeafIdx::new(5).into());
    }

    #[test]
    fn test_compute_subtree_root_multiple_leaves() {
        // Multiple leaves - should recursively compute
        let root = compute_subtree_root(0, 4);
        // This should be the root of a complete binary tree with 4 leaves
        assert_eq!(root, root_idx(4));

        // Test non-power-of-2 range
        let root = compute_subtree_root(0, 3);
        // Should handle the unbalanced tree correctly
        assert_ne!(root.as_u64(), 0);
    }

    #[test]
    fn test_consistency_proof_comprehensive() {
        // Test various tree size combinations
        struct TestCase {
            old_size: u64,
            new_size: u64,
            expected_indices_count: usize,
        }

        let test_cases = vec![
            TestCase {
                old_size: 1,
                new_size: 2,
                expected_indices_count: 1,
            },
            TestCase {
                old_size: 1,
                new_size: 3,
                expected_indices_count: 2,
            },
            TestCase {
                old_size: 1,
                new_size: 4,
                expected_indices_count: 2,
            },
            TestCase {
                old_size: 2,
                new_size: 3,
                expected_indices_count: 1,
            },
            TestCase {
                old_size: 2,
                new_size: 4,
                expected_indices_count: 1,
            },
            TestCase {
                old_size: 3,
                new_size: 7,
                expected_indices_count: 4,
            }, // Updated count
            TestCase {
                old_size: 4,
                new_size: 8,
                expected_indices_count: 1,
            },
            TestCase {
                old_size: 6,
                new_size: 10,
                expected_indices_count: 4,
            },
        ];

        for tc in test_cases {
            let indices = indices_for_consistency_proof(tc.old_size, tc.new_size - tc.old_size);
            assert_eq!(
                indices.len(),
                tc.expected_indices_count,
                "Failed for old_size={}, new_size={}",
                tc.old_size,
                tc.new_size
            );
        }
    }
}
