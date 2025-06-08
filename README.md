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
3. **Synchronous tree updates** - achieving a Maximum Merge Delay (MMD) of 0 seconds.

### How MMD is Set to Zero

Many CT log implementations have a Maximum Merge Delay (MMD) of minutes to hours, where submitted certificates aren't yet included in the Merkle tree. This exists because:

- Many implementations issue SCTs immediately, then incorporate certificates later via background processes.
- Some implementations have expensive tree update operations.
- Consistency requires coordinating distributed components.

CompactLog achieves an MMD of 0 by reversing this order - certificates are incorporated **before** SCTs are issued:

```
Submission 1 ─┐
Submission 2 ─┼─ Wait up to 500ms ─→ Batch tree update ─→ All SCTs returned
Submission 3 ─┘                             └── Certificates already incorporated
```

The 500ms delay is submission latency, not MMD. Once SCTs are issued, certificates are already in the tree, giving us an MMD of 0.

The batching system:

- Collects submissions for up to 500ms (configurable) to form a batch
- Updates the Merkle tree once for the entire batch
- Returns SCTs only after certificates are incorporated in the tree
- No background processing - certificates are immediately available for proofs

This achieves both efficiency and an MMD of 0 because:

1. STH-boundary versioning makes batch updates efficient
2. Synchronous processing eliminates the post-SCT "merge" phase entirely
3. Bounded submission latency - max 500ms wait, but often less with high traffic

### Traditional vs CompactLog Timing

**Traditional CT implementations:**

```
Submit cert → Issue SCT immediately → [MMD period] → Incorporate in tree
```

**CompactLog:**

```
Submit cert → [Batch delay ≤500ms] → Incorporate in tree → Issue SCT
```

Result: Traditional logs have MMD measured in minutes/hours; CompactLog has an MMD of 0 seconds.

### STH-Boundary Versioning

CompactLog versions nodes only at STH publication boundaries:

- Update nodes in-memory during batch operations  
- Store O(log n) versioned nodes only at STH publication
- With STHs every k certificates: reduces versioned storage from O(n log n) to O(n log n / k)

**Example**: Publishing STHs every 1000 certificates reduces versioned storage overhead by 1000x.

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
cert_sct:{cert_hash} → SCT data

# Certificate storage (deduplication)
cert:{cert_hash} → certificate binary data
entry:{index} → deduplicated log entry
```

### Certificate Chain Deduplication

CompactLog stores certificate chains using content-addressable storage:

1. **Entry structure**: Each log entry stores SHA-256 hashes of certificates rather than the certificates themselves
2. **Certificate store**: Certificates are stored separately under `cert:{hash}` keys
3. **Deduplication**: Multiple entries referencing the same certificate (e.g., intermediate CA certs) share the same stored copy
4. **Reconstruction**: The API reconstructs full certificate chains by resolving hash references during retrieval

The `DeduplicatedLogEntry` structure contains:
- Certificate hash (32 bytes)
- Chain certificate hashes (array of 32-byte hashes)
- Original metadata (timestamp, index, entry type)

### Consistency Model

Every operation maintains strict consistency:

- Reads see the latest committed STH state
- Writes are serialized through asynchronous locking (synchronous from client perspective)
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
