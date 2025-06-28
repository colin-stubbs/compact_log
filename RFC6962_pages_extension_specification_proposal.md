# RFC 6962 Pages Extension Specification Proposal

## Abstract

This document specifies a simple extension to RFC 6962 Certificate Transparency logs that enables efficient caching and batch retrieval through page-based access patterns with a binary format that eliminates base64 encoding and chain duplication.

## 1. Introduction

The RFC 6962 `get-entries` endpoint accepts arbitrary start/end parameters, making caching difficult and responses inefficient due to base64 encoding and duplicate certificate chains. This extension introduces page-based access with an efficient binary format while maintaining full backward compatibility.

## 2. Page-Based Entry Retrieval

### 2.1 Request Format

```http
GET /ct-pages/v1/page/{page_number}
```

Where `page_number` is a non-negative integer (0-indexed).

### 2.2 Response Format

#### Headers

```http
Content-Type: application/octet-stream
CT-Page-Size: 1000
CT-Entry-Range: 42000-42999
Cache-Control: public, max-age=31536000, immutable
```

For the last (potentially partial) page:
```http
CT-Entry-Range: 8765000-8765431
Cache-Control: no-store
```

#### Binary Response Structure

```c
enum { v1(0), (255) } Version;

struct {
    Version format_version;  // v1(0)
    uint64 entry_count;
    uint64 first_entry_index;
    PageEntry entries[entry_count];
} EntriesPage;

struct {
    TimestampedEntry timestamped_entry;  // Reuse RFC 6962 struct
    uint16 chain_length;
    opaque issuer_hashes[chain_length][32];  // SHA-256 hashes
} PageEntry;
```

### 2.3 Certificate Resolution

Issuer certificates are fetched separately and cached:

```http
GET /ct-pages/v1/certificate/{base64url_sha256_hash}

Content-Type: application/pkix-cert
Cache-Control: public, max-age=31536000, immutable

[binary certificate data]
```

### 2.4 Discovery

Logs MUST provide a discovery endpoint:

```http
GET /ct-pages/v1/discover

Content-Type: application/json

{
  "page_size": 1000,
  "static_endpoint": "https://static.example.com",  // Optional
}
```

If `static_endpoint` is provided, clients MUST use it for fetching pages and certificates.

## 3. Backward Compatibility

The original RFC 6962 endpoints remain unchanged. This extension introduces new endpoints under `/ct-pages/v1/` that:
- MUST be served on the same host as the main log endpoints, UNLESS a separate static serving endpoint is provided via the discovery mechanism
- Do not interfere with existing `/ct/v1/*` endpoints
- Allow clients to opt-in to the new format
- Maintain full compatibility with RFC 6962 clients

## 4. Operational Considerations

### 4.1 Page Size Stability

Once a log begins serving pages, it MUST NOT change the page size, as this would invalidate cached responses and complicate client logic.

### 4.2 Static Deployment

Since pages are immutable once full, logs can pre-generate pages.
