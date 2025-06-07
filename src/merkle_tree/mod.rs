// Vendored code from ct-merkle library
pub mod ct_merkle_vendored;

pub mod consistency;
pub mod slatedb_backed_tree;

// Re-export types from the vendored module
pub use ct_merkle_vendored::{ConsistencyProof, InclusionProof, RootHash};
pub use slatedb_backed_tree::SlateDbBackedTree;
