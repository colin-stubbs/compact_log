# CT Log Benchmarking Tools

This directory contains tools for benchmarking Certificate Transparency (CT) log servers.

## Quick Start

### 1. Generate Test Certificates

```bash
# Generate 10,000 test certificates
cargo run --release --bin gen_certs -- 10000 ./certs
```

This creates:
- `./certs/ca.crt` - CA certificate
- `./certs/ca.key` - CA private key
- `./certs/chains.pem` - All certificate chains (each cert + CA)

### 2. Run Benchmark with wrk

```bash
# Basic benchmark (12 threads, 400 connections, 30 seconds)
wrk -s ct_bench_pem.lua -t12 -c400 -d30s http://localhost:8080

# Longer benchmark with more connections
wrk -s ct_bench_pem.lua -t24 -c1000 -d5m http://localhost:8080

# Show detailed latency distribution
wrk -s ct_bench_pem.lua -t12 -c400 -d30s --latency http://localhost:8080
```

## How It Works

1. **Certificate Generation** (`gen_certs`):
   - Creates an ECDSA CA using P-256 curve
   - Generates unique certificates with CNs like `bench-{index}.example.com`
   - Outputs all chains in PEM format for easy loading

2. **Benchmark Script** (`ct_bench_pem.lua`):
   - Loads all certificate chains into memory at startup
   - Each request randomly selects a certificate from the pool
   - Submits to `/ct/v1/add-chain` endpoint as JSON
