use crate::api::{ApiState, ErrorResponse};
use crate::types::pages::{base64url_to_hash, DiscoveryResponse, EntriesPage};
use crate::types::DeduplicatedLogEntry;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use std::sync::Arc;

type ApiResult<T> = std::result::Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;

const PAGE_SIZE: u64 = 1000;

pub async fn discover() -> ApiResult<DiscoveryResponse> {
    Ok(Json(DiscoveryResponse {
        page_size: PAGE_SIZE,
        static_endpoint: None,
    }))
}

pub async fn get_page(
    State(state): State<Arc<ApiState>>,
    Path(page_number): Path<u64>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let start_index = page_number * PAGE_SIZE;
    let end_index = start_index + PAGE_SIZE;

    // Get current tree size
    let tree_size = state.merkle_tree.size().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get tree size: {}", e),
            }),
        )
    })?;

    if start_index >= tree_size {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!(
                    "Page not found. Page number: {}, tree size: {}, max page: {}",
                    page_number,
                    tree_size,
                    tree_size / PAGE_SIZE
                ),
            }),
        ));
    }

    // Determine actual end index (might be less than page_size for the last page)
    let actual_end = end_index.min(tree_size);

    // Create the page
    let mut page = EntriesPage::new(start_index);

    // Fetch entries from storage
    for index in start_index..actual_end {
        let entry = state
            .storage
            .get_deduplicated_entry(index)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to retrieve entry: {}", e),
                    }),
                )
            })?;

        if let Some(entry) = entry {
            // Serialize the TimestampedEntry according to RFC 6962
            let timestamped_entry = serialize_timestamped_entry(&entry).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: e }),
                )
            })?;

            // Convert chain hashes to the expected format
            let issuer_hashes = entry
                .chain_hashes
                .as_ref()
                .map(|hashes| hashes.clone())
                .unwrap_or_default();

            page.add_entry(timestamped_entry, issuer_hashes);
        } else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Missing entry in log at index: {}", index),
                }),
            ));
        }
    }

    // Convert to binary format
    let binary_data = page.to_binary();

    // Build headers
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    headers.insert("CT-Page-Size", PAGE_SIZE.to_string().parse().unwrap());
    headers.insert(
        "CT-Entry-Range",
        format!("{}-{}", start_index, actual_end - 1)
            .parse()
            .unwrap(),
    );

    // Set cache control based on whether this is a complete page
    if actual_end == end_index && actual_end < tree_size {
        // Complete page that won't change
        headers.insert(
            header::CACHE_CONTROL,
            "public, max-age=31536000, immutable".parse().unwrap(),
        );
    } else {
        // Partial page (last page) - don't cache
        headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }

    Ok((headers, binary_data).into_response())
}

pub async fn get_certificate(
    State(state): State<Arc<ApiState>>,
    Path(hash_str): Path<String>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Decode the base64url hash
    let hash = base64url_to_hash(&hash_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid certificate hash: {}", e),
            }),
        )
    })?;

    // Retrieve the certificate from storage
    let cert_data = state.storage.get_certificate(&hash).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to retrieve certificate: {}", e),
            }),
        )
    })?;

    if let Some(cert_data) = cert_data {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/pkix-cert".parse().unwrap(),
        );
        headers.insert(
            header::CACHE_CONTROL,
            "public, max-age=31536000, immutable".parse().unwrap(),
        );

        Ok((headers, cert_data).into_response())
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Certificate not found for hash: {}", hash_str),
            }),
        ))
    }
}

fn serialize_timestamped_entry(entry: &DeduplicatedLogEntry) -> Result<Vec<u8>, String> {
    // The DeduplicatedLogEntry already contains the serialized MerkleTreeLeaf data
    // which is the TimestampedEntry in RFC 6962 format
    // We need to extract just the TimestampedEntry part (skip the MerkleTreeLeaf version and type)

    // MerkleTreeLeaf structure:
    // - Version (1 byte) - always 0
    // - LeafType (1 byte) - always 0 (timestamped_entry)
    // - TimestampedEntry (rest of the data)

    if entry.leaf_data.len() < 2 {
        return Err(format!(
            "Invalid leaf data: too short (length: {})",
            entry.leaf_data.len()
        ));
    }

    // Skip the first 2 bytes (version and leaf type) to get the TimestampedEntry
    Ok(entry.leaf_data[2..].to_vec())
}
