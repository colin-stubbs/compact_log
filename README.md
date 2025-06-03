<p align="center">
  <img src="assets/readme_illustration.png" alt="README Illustration" style="border-radius: 10px;" width="600" />
</p>

**⚠️ This is a work in progress. While the CT functionality works, this should not be yet used in production.**

# CompactLog

A Certificate Transparency (CT) log implementation using SlateDB's LSM-tree storage engine with object storage backend. CompactLog implements RFC 6962 Certificate Transparency APIs on top of SlateDB to explore how LSM-tree storage can address traditional CT log scalability challenges.

## Overview

This implementation provides a complete Certificate Transparency log that:
- Accepts X.509 certificate chains and pre-certificates
- Issues Signed Certificate Timestamps (SCTs)
- Maintains a cryptographically verifiable Merkle tree
- Provides inclusion and consistency proofs
- Stores data in cloud object storage (S3, Azure Blob) or local filesystem

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CT API        │    │   Merkle Tree    │    │   SlateDB       │
│   (RFC 6962)    │───▶│   Operations     │───▶│   LSM-Tree      │
│                 │    │                  │    │                 │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • add-chain     │    │ • Root Hash      │    │ • Write Batching│
│ • add-pre-chain │    │ • Inclusion      │    │ • Compaction    │
│ • get-sth       │    │ • Consistency    │    │ • Hash Caching  │
│ • get-entries   │    │ • Verification   │    │ • Cloud Storage │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Storage Design

The implementation uses SlateDB's LSM-tree for persistent storage with these key patterns:
- **Log entries**: Stored as `entry:<index>` with serialized certificate data
- **Merkle tree state**: Leaf hashes cached for efficient root computation
- **Signed Tree Heads**: Cached per tree size to avoid recomputation
- **Hash mappings**: Direct lookup from leaf hash to tree index

### Approach to Scalability

Rather than implementing tile-based storage (as proposed in newer CT designs), this project explores whether LSM-tree characteristics can provide similar benefits:
- **Write optimization**: LSM-trees handle high write throughput naturally
- **Batched operations**: Configurable batching without external complexity
- **Cloud storage**: Direct integration with object stores for scaling
- **Caching strategies**: Strategic caching of computed hashes and proofs

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
