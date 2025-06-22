use crate::api::{ApiState, ErrorResponse};
use crate::merkle_tree::compute_subtree_root;
use crate::metrics;
use crate::types::tiles::{parse_tile_index, DataTile, Tile, TileLeaf};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use flate2::write::GzEncoder;
use flate2::Compression;
use futures::stream::{self, StreamExt, TryStreamExt};
use std::io::Write;
use std::sync::Arc;

/// Get the checkpoint for this log following the C2SP specification
pub async fn get_checkpoint(
    State(state): State<Arc<ApiState>>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    let committed_root = state.merkle_tree.committed_root().await.map_err(|e| {
        metrics::STATIC_CT_CHECKPOINT_REQUESTS
            .with_label_values(&["error"])
            .inc();
        (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into()))
    })?;

    let tree_size = committed_root.num_leaves();
    let root_hash = committed_root.as_bytes().to_vec();

    let timestamp = chrono::Utc::now().timestamp_millis() as u64;
    let checkpoint = state
        .sth_builder
        .create_checkpoint(tree_size, root_hash, Some(timestamp))
        .map_err(|e| {
            metrics::STATIC_CT_CHECKPOINT_REQUESTS
                .with_label_values(&["error"])
                .inc();
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into()))
        })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "max-age=5, must-revalidate")
        .body(checkpoint.format())
        .map_err(|_| {
            metrics::STATIC_CT_CHECKPOINT_REQUESTS
                .with_label_values(&["error"])
                .inc();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    metrics::STATIC_CT_CHECKPOINT_REQUESTS
        .with_label_values(&["success"])
        .inc();

    Ok(response.into_response())
}

pub async fn get_tile(
    State(state): State<Arc<ApiState>>,
    Path((level, index_path, width)): Path<(u8, String, Option<u16>)>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    if level > 5 {
        metrics::STATIC_CT_TILE_REQUESTS
            .with_label_values(&["merkle", "error"])
            .inc();
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Invalid tile level, must be 0-5".to_string(),
            }),
        ));
    }

    let tile_index = parse_tile_index(&index_path).map_err(|e| {
        metrics::STATIC_CT_TILE_REQUESTS
            .with_label_values(&["merkle", "error"])
            .inc();
        (
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: format!("Invalid tile index: {}", e),
            }),
        )
    })?;

    if let Some(w) = width {
        if w == 0 || w > 256 {
            metrics::STATIC_CT_TILE_REQUESTS
                .with_label_values(&["merkle", "error"])
                .inc();
            return Err((
                StatusCode::BAD_REQUEST,
                axum::Json(ErrorResponse {
                    error: "Invalid tile width, must be 1-256".to_string(),
                }),
            ));
        }
    }

    let committed_root = state.merkle_tree.committed_root().await.map_err(|e| {
        metrics::STATIC_CT_TILE_REQUESTS
            .with_label_values(&["merkle", "error"])
            .inc();
        (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into()))
    })?;
    let tree_size = committed_root.num_leaves();

    let tile = generate_merkle_tile(&state, level, tile_index, tree_size, width)
        .await
        .inspect_err(|_| {
            metrics::STATIC_CT_TILE_REQUESTS
                .with_label_values(&["merkle", "error"])
                .inc();
        })?;

    if level == 1 && tile_index == 3 {
        tracing::debug!(
            "Generating level 1 tile 3 with tree_size={} root_hash={:?}",
            tree_size,
            hex::encode(&committed_root.as_bytes()[..8])
        );
    }

    let tile_data = tile.to_bytes();

    metrics::STATIC_CT_TILE_SIZE_BYTES
        .with_label_values(&["merkle"])
        .observe(tile_data.len() as f64);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Body::from(tile_data))
        .map_err(|_| {
            metrics::STATIC_CT_TILE_REQUESTS
                .with_label_values(&["merkle", "error"])
                .inc();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    metrics::STATIC_CT_TILE_REQUESTS
        .with_label_values(&["merkle", "success"])
        .inc();

    Ok(response)
}

async fn generate_merkle_tile(
    state: &ApiState,
    level: u8,
    tile_index: u64,
    tree_size: u64,
    requested_width: Option<u16>,
) -> Result<Tile, (StatusCode, axum::Json<ErrorResponse>)> {
    let nodes_per_tile = 256u64;

    let max_hashes = if let Some(w) = requested_width {
        w as u64
    } else {
        // Calculate width according to spec: floor(s / 256**l) mod 256
        let subtree_size = 256u64.pow(level as u32);

        // Calculate total positions, including partial subtrees
        // If there are remaining leaves after the last full subtree, we have one more position
        let full_subtrees = tree_size / subtree_size;
        let has_partial_subtree = (tree_size % subtree_size) > 0;
        let total_positions = full_subtrees + if has_partial_subtree { 1 } else { 0 };

        let full_tiles = total_positions / 256;
        let partial_width = total_positions % 256;

        if tile_index < full_tiles {
            // This is a full tile
            nodes_per_tile
        } else if tile_index == full_tiles && partial_width > 0 {
            // This is the partial tile
            partial_width
        } else {
            // This tile doesn't exist
            0
        }
    };

    if max_hashes == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(ErrorResponse {
                error: "Tile not found".to_string(),
            }),
        ));
    }

    const CONCURRENCY_LIMIT: usize = 32;

    let hashes: Vec<[u8; 32]> = stream::iter(0..max_hashes)
        .map(|i| {
            let position_in_tile = i;
            let subtree_size = 256u64.pow(level as u32);
            let start_leaf = (tile_index * 256 + position_in_tile) * subtree_size;
            let merkle_tree = state.merkle_tree.clone();

            async move {
                if start_leaf >= tree_size {
                    Ok(None)
                } else {
                    let end_leaf = std::cmp::min(start_leaf + subtree_size, tree_size);
                    let actual_subtree_size = end_leaf - start_leaf;
                    let subtree_root_idx = compute_subtree_root(start_leaf, end_leaf);

                    if actual_subtree_size < subtree_size {
                        tracing::debug!(
                            "Computing incomplete subtree: level={} tile={} pos={} start={} end={} size={} idx={}",
                            level, tile_index, position_in_tile, start_leaf, end_leaf, actual_subtree_size, subtree_root_idx.as_u64()
                        );
                    }

                    let hash = merkle_tree
                        .get_node_hash_at_version(subtree_root_idx.as_u64(), tree_size)
                        .await?;

                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(hash.as_slice());
                    Ok::<Option<[u8; 32]>, crate::types::CtError>(Some(hash_array))
                }
            }
        })
        .buffered(CONCURRENCY_LIMIT)
        .try_filter_map(|x| async move { Ok(x) })
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: format!("Failed to get node hash: {}", e),
                }),
            )
        })?;

    if hashes.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(ErrorResponse {
                error: "Tile not found".to_string(),
            }),
        ));
    }

    Ok(Tile::new(hashes))
}

pub async fn get_data_tile(
    State(state): State<Arc<ApiState>>,
    Path((index_path, width)): Path<(String, Option<u16>)>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    let tile_index = parse_tile_index(&index_path).map_err(|e| {
        metrics::STATIC_CT_TILE_REQUESTS
            .with_label_values(&["data", "error"])
            .inc();
        (
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: format!("Invalid tile index: {}", e),
            }),
        )
    })?;

    if let Some(w) = width {
        if w == 0 || w > 256 {
            metrics::STATIC_CT_TILE_REQUESTS
                .with_label_values(&["data", "error"])
                .inc();
            return Err((
                StatusCode::BAD_REQUEST,
                axum::Json(ErrorResponse {
                    error: "Invalid tile width, must be 1-256".to_string(),
                }),
            ));
        }
    }

    let committed_root = state.merkle_tree.committed_root().await.map_err(|e| {
        metrics::STATIC_CT_TILE_REQUESTS
            .with_label_values(&["data", "error"])
            .inc();
        (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(e.into()))
    })?;
    let tree_size = committed_root.num_leaves();

    let data_tile = generate_data_tile(&state, tile_index, tree_size, width)
        .await
        .inspect_err(|_| {
            metrics::STATIC_CT_TILE_REQUESTS
                .with_label_values(&["data", "error"])
                .inc();
        })?;

    // Always compress data tiles with gzip as per spec
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&data_tile.data).map_err(|_| {
        metrics::STATIC_CT_TILE_REQUESTS
            .with_label_values(&["data", "error"])
            .inc();
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Failed to compress data tile".to_string(),
            }),
        )
    })?;
    let compressed = encoder.finish().map_err(|_| {
        metrics::STATIC_CT_TILE_REQUESTS
            .with_label_values(&["data", "error"])
            .inc();
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse {
                error: "Failed to finish compression".to_string(),
            }),
        )
    })?;

    metrics::STATIC_CT_TILE_SIZE_BYTES
        .with_label_values(&["data"])
        .observe(compressed.len() as f64);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_ENCODING, "gzip")
        .header(header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Body::from(compressed))
        .map_err(|_| {
            metrics::STATIC_CT_TILE_REQUESTS
                .with_label_values(&["data", "error"])
                .inc();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    metrics::STATIC_CT_TILE_REQUESTS
        .with_label_values(&["data", "success"])
        .inc();

    Ok(response)
}

async fn generate_data_tile(
    state: &ApiState,
    tile_index: u64,
    tree_size: u64,
    requested_width: Option<u16>,
) -> Result<DataTile, (StatusCode, axum::Json<ErrorResponse>)> {
    let entries_per_tile = 256u64;
    let start_offset = tile_index * entries_per_tile;

    let max_entries = if let Some(w) = requested_width {
        w as u64
    } else {
        entries_per_tile
    };

    const CONCURRENCY_LIMIT: usize = 32;

    let leaf_bytes_vec: Vec<Vec<u8>> = stream::iter(0..max_entries)
        .map(|i| {
            let entry_index = start_offset + i;
            let storage = state.storage.clone();

            async move {
                if entry_index >= tree_size {
                    Ok(None)
                } else {
                    let entry = storage
                        .get_deduplicated_entry(entry_index)
                        .await?
                        .ok_or_else(|| {
                            crate::types::CtError::Internal(format!(
                                "Entry {} not found",
                                entry_index
                            ))
                        })?;

                    let pre_certificate =
                        if entry.entry_type == crate::types::LogEntryType::PrecertEntry {
                            if let Some(precert_hash) = &entry.original_precert_hash {
                                storage.get_certificate(precert_hash).await?
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                    let tile_leaf = TileLeaf::from_entry(&entry, pre_certificate);
                    let leaf_bytes = tile_leaf.to_bytes();

                    Ok::<Option<Vec<u8>>, crate::types::CtError>(Some(leaf_bytes))
                }
            }
        })
        .buffered(CONCURRENCY_LIMIT)
        .try_filter_map(|x| async move { Ok(x) })
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: format!("Failed to get entry data: {}", e),
                }),
            )
        })?;

    if leaf_bytes_vec.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(ErrorResponse {
                error: "Data tile not found".to_string(),
            }),
        ));
    }

    let mut data = Vec::new();
    for leaf_bytes in leaf_bytes_vec {
        data.extend_from_slice(&leaf_bytes);
    }

    Ok(DataTile { data })
}

pub async fn get_issuer(
    State(state): State<Arc<ApiState>>,
    Path(fingerprint): Path<String>,
) -> Result<Response, (StatusCode, axum::Json<ErrorResponse>)> {
    let fingerprint_bytes = hex::decode(&fingerprint).map_err(|_| {
        metrics::STATIC_CT_ISSUER_REQUESTS
            .with_label_values(&["error"])
            .inc();
        (
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Invalid fingerprint format, must be hex-encoded".to_string(),
            }),
        )
    })?;

    if fingerprint_bytes.len() != 32 {
        metrics::STATIC_CT_ISSUER_REQUESTS
            .with_label_values(&["error"])
            .inc();
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: "Invalid fingerprint length, must be 32 bytes (64 hex chars)".to_string(),
            }),
        ));
    }

    let mut fingerprint_array = [0u8; 32];
    fingerprint_array.copy_from_slice(&fingerprint_bytes);

    let certificate = state
        .storage
        .get_certificate(&fingerprint_array)
        .await
        .map_err(|e| {
            metrics::STATIC_CT_ISSUER_REQUESTS
                .with_label_values(&["error"])
                .inc();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: format!("Failed to get certificate: {}", e),
                }),
            )
        })?
        .ok_or_else(|| {
            metrics::STATIC_CT_ISSUER_REQUESTS
                .with_label_values(&["not_found"])
                .inc();
            (
                StatusCode::NOT_FOUND,
                axum::Json(ErrorResponse {
                    error: "Certificate not found".to_string(),
                }),
            )
        })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pkix-cert")
        .header(header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Body::from(certificate))
        .map_err(|_| {
            metrics::STATIC_CT_ISSUER_REQUESTS
                .with_label_values(&["error"])
                .inc();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse {
                    error: "Failed to build response".to_string(),
                }),
            )
        })?;

    metrics::STATIC_CT_ISSUER_REQUESTS
        .with_label_values(&["success"])
        .inc();

    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::types::signed_note::SignedNote;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn test_checkpoint_format_parsing() {
        let checkpoint_text = r#"example.com/log
12345
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

— example.com/log Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8="#;

        let lines: Vec<&str> = checkpoint_text.lines().collect();

        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "example.com/log");
        assert_eq!(lines[1], "12345");
        assert!(lines[2].len() > 0);
        assert_eq!(lines[3], "");
        assert!(lines[4].starts_with("— example.com/log "));

        let sig_parts: Vec<&str> = lines[4].split_whitespace().collect();
        assert_eq!(sig_parts[0], "—");
        assert_eq!(sig_parts[1], "example.com/log");

        let sig_bytes = STANDARD.decode(sig_parts[2]).expect("Invalid base64");
        assert!(sig_bytes.len() > 4);
    }

    #[test]
    fn test_origin_extraction_from_base_url() {
        let test_cases = vec![
            ("https://example.com/log/", "example.com/log"),
            ("http://localhost:8080/", "localhost:8080"),
            ("https://ct.example.org/2024h1/", "ct.example.org/2024h1"),
            ("http://test.com", "test.com"),
        ];

        for (base_url, expected_origin) in test_cases {
            let origin = base_url
                .trim_end_matches('/')
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            assert_eq!(origin, expected_origin);
        }
    }

    #[test]
    fn test_signed_note_formatting() {
        let note = SignedNote::new(
            "example.com/log\n0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string(),
        );

        let formatted = note.format();

        let lines: Vec<&str> = formatted.lines().collect();
        assert_eq!(lines[0], "example.com/log");
        assert_eq!(lines[1], "0");
        assert_eq!(lines[2], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(lines[3], "");
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn test_partial_tile_width_calculation() {
        let test_cases = vec![
            (70000, 0, 112),
            (70000, 1, 17),
            (70000, 2, 1),
            (256, 0, 0),
            (256, 1, 1),
            (512, 0, 0),
            (512, 1, 2),
            (1, 0, 1),
            (257, 0, 1),
        ];

        for (tree_size, level, expected_width) in test_cases {
            let subtree_size = 256u64.pow(level as u32);
            let total_positions = tree_size / subtree_size;
            let partial_width = (total_positions % 256) as u64;

            assert_eq!(
                partial_width, expected_width,
                "For tree_size={} at level={}, expected width {} but got {}",
                tree_size, level, expected_width, partial_width
            );
        }
    }

    #[test]
    fn test_tile_level_validation() {
        // Test that levels 0-5 are valid
        for level in 0..=5 {
            // Valid levels should pass the check
            assert!(level <= 5, "Level {} should be valid", level);
        }

        // Test that levels above 5 are invalid
        for level in 6..=10 {
            assert!(level > 5, "Level {} should be invalid", level);
        }
    }

    #[test]
    fn test_tile_index_parsing_edge_cases() {
        use crate::types::tiles::parse_tile_index;

        assert_eq!(
            parse_tile_index("x999/x999/x999/999").unwrap(),
            999999999999u64
        );

        let long_path = "x001/x002/x003/x004/x005/006";
        assert_eq!(parse_tile_index(long_path).unwrap(), 1002003004005006u64);

        assert!(parse_tile_index("x1000/000").is_err());
        assert!(parse_tile_index("001/x002").is_err());
        assert!(parse_tile_index("x00/123").is_err());
        assert!(parse_tile_index("x123/45").is_err());
    }
}
