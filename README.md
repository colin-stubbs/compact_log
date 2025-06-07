<p align="center">
  <img src="assets/readme_illustration.png" alt="README Illustration" style="border-radius: 10px;" width="600" />
</p>

**⚠️ This is a work in progress. While the CT functionality works, this should not be yet used in production.**

# CompactLog

A Certificate Transparency (CT) log implementation. CompactLog implements RFC 6962 Certificate Transparency APIs on top of SlateDB to explore how LSM-tree storage can address traditional CT log scalability challenges.

## Overview

This implementation provides a complete Certificate Transparency log that:
- Accepts X.509 certificate chains and pre-certificates
- Issues Signed Certificate Timestamps (SCTs)
- Maintains a cryptographically verifiable Merkle tree
- Provides inclusion and consistency proofs
- Stores data in cloud object storage (S3, Azure Blob) or local filesystem

## Storage Architecture

### Core Design Decisions

CompactLog makes three fundamental design choices that differentiate it from other CT implementations:

1. **LSM-tree storage via SlateDB** instead of relational databases or custom storage engines.
2. **STH-boundary versioning** - only persisting tree state at published checkpoints.
3. **Synchronous tree updates** - eliminating the Maximum Merge Delay (MMD) entirely.

### How MMD is Eliminated

Many CT log implementations have a Maximum Merge Delay - a window where submitted certificates aren't yet included in the Merkle tree. This exists because:

- Some implementations have expensive tree update operations
- Background signers batch updates for efficiency
- Consistency requires coordinating distributed components

CompactLog eliminates MMD through **immediate consistency with intelligent batching**:

```
Submission 1 ─┐
Submission 2 ─┼─ Wait up to 500ms ─→ Batch update ─→ All SCTs returned
Submission 3 ─┘                       └── Single atomic tree update
```

The batching system:

- Blocks submitters for up to 500ms (configurable) to collect a batch
- Updates the tree once for the entire batch (not per certificate)
- Returns SCTs immediately after the batch commits
- No background processing - submitters get proof-ready SCTs synchronously

This achieves both efficiency and immediate consistency because:

1. STH-boundary versioning makes batch updates cheap (only final state stored)
2. Synchronous batching eliminates the separate "merge" phase
3. Bounded latency - max 500ms wait, but often less with high traffic

### STH-Boundary Versioning

Merkle tree nodes are only versioned when publishing an STH, not on every update.

Example with 1000 certificates between STHs:

```
Without STH-boundary versioning:
- Store updated nodes for each certificate addition
- Storage: O(n log n) for n certificates

With STH-boundary versioning:
- Update nodes in-place during batch operations
- Store versioned nodes only at STH publication
- Storage: O(log n) per STH
```

### Storage Schema

```
# Core data
leaf:{index} → certificate/precert data
vnode:{node}@{version} → node hash (version = STH boundary)
nver:{node} → latest version of node

# Operational state
meta → current tree size
committed_size → last STH boundary
hash:{leaf_hash} → tree index
```

### Consistency Model

Every operation maintains strict consistency:

- Reads see the latest committed STH state
- Writes are serialized through async locking
- Proofs only available at STH boundaries (ensuring stable references)
- No eventual consistency - all operations are immediately visible


## Configuration

Create `Config.toml` or let the system generate defaults:

```toml
[server]
bind_addr = "0.0.0.0:8080"

[storage]
provider = "local"  # "aws", "azure", or "local"

[storage.local]
path = "/tmp/ct-log-storage"

[keys]
private_key_path = "keys/private_key.pem"
public_key_path = "keys/public_key.pem"
```

For cloud storage, configure provider-specific credentials in the respective sections.

## Running

```bash
# Start with default local configuration
cargo run --release

# With debug logging
RUST_LOG=debug cargo run --release
```

The system automatically generates ECDSA P-256 keys and default configuration if not present.
