use crate::{
    api::{ApiState, ErrorResponse},
    merkle_storage::serialization,
    types::{
        AddChainRequest, AddChainResponse, GetConsistencyProofRequest, GetConsistencyProofResponse,
        GetEntriesRequest, GetEntriesResponse, GetProofByHashRequest, GetProofByHashResponse,
        LeafEntry,
    },
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use x509_cert::der::Decode;

type ApiResult<T> = std::result::Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;

pub async fn add_chain(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<AddChainRequest>,
) -> ApiResult<AddChainResponse> {
    use crate::types::{LogEntry, LogEntryType};
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    if request.chain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Chain cannot be empty".to_string(),
            }),
        ));
    }

    let chain: std::result::Result<Vec<Vec<u8>>, _> = request
        .chain
        .iter()
        .map(|cert| STANDARD.decode(cert))
        .collect();
    let chain = chain.map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid base64 in certificate chain".to_string(),
            }),
        )
    })?;

    let cert_der = chain[0].clone();

    let _ = x509_cert::Certificate::from_der(&cert_der).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Invalid certificate format: Failed to parse certificate: {}",
                    e
                ),
            }),
        )
    })?;

    // Validate certificate chain if validator is configured
    if let Some(validator) = &state.validator {
        validator.validate_chain(&chain).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Certificate validation failed: {}", e),
                }),
            )
        })?;
    }

    // Calculate certificate hash for deduplication
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let cert_hash: [u8; 32] = hasher.finalize().into();

    if let Some(existing_sct_entry) = state
        .storage
        .get_sct_by_cert_hash(&cert_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?
    {
        let response = AddChainResponse {
            sct_version: existing_sct_entry.sct.version as u8,
            id: existing_sct_entry.sct.log_id.to_hex(),
            timestamp: existing_sct_entry.sct.timestamp,
            extensions: STANDARD.encode(&existing_sct_entry.sct.extensions),
            signature: BASE64.encode(&existing_sct_entry.sct.signature),
        };
        return Ok(Json(response));
    }

    // Check if this is actually a pre-certificate (should use add-pre-chain instead)
    let is_precert = LogEntry::is_precertificate(&cert_der).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    if is_precert {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Pre-certificates should be submitted to /ct/v1/add-pre-chain".to_string(),
            }),
        ));
    }

    // Index will be assigned by the storage layer

    let mut processed_chain = Vec::new();
    if chain.len() > 1 {
        for chain_cert in &chain[1..] {
            let chain_cert_der = chain_cert.clone();

            // Validate each chain certificate
            let _ = x509_cert::Certificate::from_der(&chain_cert_der).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid X.509 certificate in chain {}", e),
                    }),
                )
            })?;

            processed_chain.push(chain_cert_der);
        }
    }

    let timestamp = chrono::Utc::now();
    let timestamp_ms = timestamp.timestamp_millis() as u64;

    let log_entry = LogEntry::new_with_timestamp(
        0, // Temporary index, will be assigned by storage
        cert_der.clone(),
        if !processed_chain.is_empty() {
            Some(processed_chain)
        } else {
            None
        },
        timestamp,
    );

    let sct = state
        .sct_builder
        .create_sct_with_timestamp(&cert_der, LogEntryType::X509Entry, None, timestamp_ms)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

    let _assigned_index = state
        .storage
        .add_entry_batched(log_entry, cert_hash, sct.clone())
        .await
        .map_err(|e| match e {
            crate::storage::StorageError::QueueFull => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Service temporarily unavailable - system at capacity".to_string(),
                }),
            ),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())),
        })?;

    let response = AddChainResponse {
        sct_version: sct.version as u8,
        id: sct.log_id.to_hex(),
        timestamp: sct.timestamp,
        extensions: STANDARD.encode(&sct.extensions),
        signature: BASE64.encode(&sct.signature),
    };

    Ok(Json(response))
}

pub async fn add_pre_chain(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<AddChainRequest>,
) -> ApiResult<AddChainResponse> {
    use crate::types::{LogEntry, LogEntryType};
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    if request.chain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Chain cannot be empty".to_string(),
            }),
        ));
    }

    let chain: std::result::Result<Vec<Vec<u8>>, _> = request
        .chain
        .iter()
        .map(|cert| STANDARD.decode(cert))
        .collect();

    let chain = chain.map_err(|_e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid base64 in certificate chain".to_string(),
            }),
        )
    })?;

    let precert_der = chain[0].clone();

    let is_precert = LogEntry::is_precertificate(&precert_der).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    if !is_precert {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Certificate is not a pre-certificate (missing poison extension)"
                    .to_string(),
            }),
        ));
    }

    let mut processed_chain = Vec::new();
    if chain.len() > 1 {
        for chain_cert in &chain[1..] {
            let chain_cert_der = chain_cert.clone();

            let _ = x509_cert::Certificate::from_der(&chain_cert_der).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid X.509 certificate in chain {}", e.to_string()),
                    }),
                )
            })?;

            processed_chain.push(chain_cert_der);
        }
    }

    let mut complete_chain = vec![precert_der.clone()];
    complete_chain.extend(processed_chain.clone());

    // Validate certificate chain if validator is configured
    if let Some(validator) = &state.validator {
        validator.validate_chain(&complete_chain).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Certificate validation failed: {}", e),
                }),
            )
        })?;
    }

    let issuer_key_hash = LogEntry::extract_issuer_key_hash(&complete_chain).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let tbs_certificate = LogEntry::remove_poison_extension(&precert_der).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    // Calculate certificate hash for deduplication (using TBS certificate for pre-certs)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&tbs_certificate);
    hasher.update(&issuer_key_hash);
    let cert_hash: [u8; 32] = hasher.finalize().into();

    if let Some(existing_sct_entry) = state
        .storage
        .get_sct_by_cert_hash(&cert_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?
    {
        let response = AddChainResponse {
            sct_version: existing_sct_entry.sct.version as u8,
            id: existing_sct_entry.sct.log_id.to_hex(),
            timestamp: existing_sct_entry.sct.timestamp,
            extensions: STANDARD.encode(&existing_sct_entry.sct.extensions),
            signature: BASE64.encode(&existing_sct_entry.sct.signature),
        };
        return Ok(Json(response));
    }

    let timestamp = chrono::Utc::now();
    let timestamp_ms = timestamp.timestamp_millis() as u64;

    let log_entry = LogEntry::new_precert_with_timestamp(
        0, // Temporary index, will be assigned by storage
        tbs_certificate.clone(),
        if !processed_chain.is_empty() {
            Some(processed_chain)
        } else {
            None
        },
        issuer_key_hash.clone(),
        precert_der.clone(),
        timestamp,
    );

    let sct = state
        .sct_builder
        .create_sct_with_timestamp(
            &tbs_certificate,
            LogEntryType::PrecertEntry,
            Some(&issuer_key_hash),
            timestamp_ms,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

    let _assigned_index = state
        .storage
        .add_entry_batched(log_entry, cert_hash, sct.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

    let response = AddChainResponse {
        sct_version: sct.version as u8,
        id: sct.log_id.to_hex(),
        timestamp: sct.timestamp,
        extensions: STANDARD.encode(&sct.extensions),
        signature: BASE64.encode(&sct.signature),
    };

    Ok(Json(response))
}

pub async fn get_sth(
    State(state): State<Arc<ApiState>>,
) -> ApiResult<crate::types::tree_head::SthResponse> {
    // Get the committed root (which includes the committed size)
    let committed_root = state
        .merkle_tree
        .committed_root()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

    let tree_size = committed_root.num_leaves();
    let root_hash = committed_root.as_bytes().to_vec();

    let timestamp = chrono::Utc::now().timestamp_millis() as u64;
    let sth = state
        .sth_builder
        .create_sth(tree_size, root_hash, Some(timestamp))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

    Ok(Json(sth.to_api_response()))
}

pub async fn get_sth_consistency(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<GetConsistencyProofRequest>,
) -> ApiResult<GetConsistencyProofResponse> {
    let proof = state
        .merkle_tree
        .consistency_proof_between_sizes(params.first, params.second)
        .await
        .map_err(|e| match e {
            crate::types::CtError::BadRequest(_) => (StatusCode::BAD_REQUEST, Json(e.into())),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())),
        })?;

    let response = GetConsistencyProofResponse {
        consistency: serialization::consistency_proof_to_path(&proof),
    };

    Ok(Json(response))
}

pub async fn get_proof_by_hash(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<GetProofByHashRequest>,
) -> ApiResult<GetProofByHashResponse> {
    let hash = BASE64.decode(&params.hash).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid base64 hash".to_string(),
            }),
        )
    })?;

    let leaf_index = state
        .storage
        .find_index_by_hash(&hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Leaf not found".to_string(),
                }),
            )
        })?;

    if leaf_index >= params.tree_size {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Leaf not found in requested tree size".to_string(),
            }),
        ));
    }

    let proof = state
        .merkle_tree
        .prove_inclusion_efficient(params.tree_size, leaf_index)
        .await
        .map_err(|e| match e {
            crate::types::CtError::BadRequest(_) => (StatusCode::BAD_REQUEST, Json(e.into())),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())),
        })?;

    let response = GetProofByHashResponse {
        leaf_index,
        audit_path: serialization::inclusion_proof_to_audit_path(&proof),
    };

    Ok(Json(response))
}

pub async fn get_entries(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<GetEntriesRequest>,
) -> ApiResult<GetEntriesResponse> {
    if params.start > params.end {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid range: start > end".to_string(),
            }),
        ));
    }

    const MAX_ENTRIES: u64 = 64;

    let count = (params.end - params.start + 1).min(MAX_ENTRIES);
    let end = params.start + count - 1;

    let storage = state.storage.clone();
    let futures: Vec<_> = (params.start..=end)
        .map(|i| {
            let storage = storage.clone();
            tokio::spawn(async move { storage.get_entry(i).await })
        })
        .collect();

    let results = futures::future::join_all(futures).await;

    let mut entries = Vec::new();

    for (_idx, join_result) in results.into_iter().enumerate() {
        let result = join_result.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Task join error: {}", e),
                }),
            )
        })?;

        if let Some(log_entry) =
            result.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?
        {
            let leaf_input = log_entry
                .serialize()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

            let mut extra_data = Vec::new();
            match log_entry.entry_type {
                crate::types::LogEntryType::X509Entry => {
                    // For X509ChainEntry, extra_data contains just the certificate_chain
                    if let Some(ref chain_data) = log_entry.chain {
                        // Calculate total chain length for TLS vector length prefix
                        let mut total_chain_len = 0u32;
                        for chain_cert in chain_data {
                            total_chain_len += 3 + chain_cert.len() as u32; // 3-byte length + cert data
                        }

                        // TLS variable-length vector: chain length (3 bytes)
                        extra_data.push((total_chain_len >> 16) as u8);
                        extra_data.push((total_chain_len >> 8) as u8);
                        extra_data.push(total_chain_len as u8);

                        // Each certificate in the chain: length (3 bytes) + cert data
                        for chain_cert in chain_data {
                            let cert_len = chain_cert.len() as u32;
                            extra_data.push((cert_len >> 16) as u8);
                            extra_data.push((cert_len >> 8) as u8);
                            extra_data.push(cert_len as u8);
                            extra_data.extend_from_slice(&chain_cert);
                        }
                    } else {
                        // Empty chain: just the length field (0)
                        extra_data.extend_from_slice(&[0x00, 0x00, 0x00]);
                    }
                }
                crate::types::LogEntryType::PrecertEntry => {
                    // For PrecertChainEntry, extra_data contains the whole PrecertChainEntry structure
                    // struct { ASN.1Cert pre_certificate; ASN.1Cert precertificate_chain<0..2^24-1>; }

                    // Pre_certificate length (3 bytes) + pre_certificate data (original, not TBS)
                    if let Some(ref original_precert) = log_entry.original_precert {
                        let precert_len = original_precert.len() as u32;
                        extra_data.push((precert_len >> 16) as u8);
                        extra_data.push((precert_len >> 8) as u8);
                        extra_data.push(precert_len as u8);
                        extra_data.extend_from_slice(original_precert);
                    } else {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "Missing original pre-certificate for PrecertEntry"
                                    .to_string(),
                            }),
                        ));
                    }

                    if let Some(ref chain_data) = log_entry.chain {
                        let mut total_chain_len = 0u32;
                        for chain_cert in chain_data {
                            total_chain_len += 3 + chain_cert.len() as u32; // 3-byte length + cert data
                        }

                        // TLS variable-length vector: chain length (3 bytes)
                        extra_data.push((total_chain_len >> 16) as u8);
                        extra_data.push((total_chain_len >> 8) as u8);
                        extra_data.push(total_chain_len as u8);

                        // Each certificate in the chain: length (3 bytes) + cert data
                        for chain_cert in chain_data {
                            let cert_len = chain_cert.len() as u32;
                            extra_data.push((cert_len >> 16) as u8);
                            extra_data.push((cert_len >> 8) as u8);
                            extra_data.push(cert_len as u8);
                            extra_data.extend_from_slice(&chain_cert);
                        }
                    } else {
                        // Empty chain: just the length field (0)
                        extra_data.extend_from_slice(&[0x00, 0x00, 0x00]);
                    }
                }
            }

            let leaf_entry = LeafEntry {
                leaf_input: BASE64.encode(&leaf_input),
                extra_data: BASE64.encode(&extra_data),
            };

            entries.push(leaf_entry);
        }
    }

    Ok(Json(GetEntriesResponse { entries }))
}

pub async fn get_roots(State(state): State<Arc<ApiState>>) -> ApiResult<GetRootsResponse> {
    if let Some(validator) = &state.validator {
        let root_certs = validator
            .get_accepted_root_certificates()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

        let (start_time, end_time) = validator.get_temporal_window();

        // Convert DER certificates to base64
        let certificates = root_certs
            .into_iter()
            .map(|cert_der| BASE64.encode(&cert_der))
            .collect();

        tracing::debug!(
            "Certificate acceptance window: {} to {}",
            start_time.format("%Y-%m-%d %H:%M:%S UTC"),
            end_time.format("%Y-%m-%d %H:%M:%S UTC")
        );

        Ok(Json(GetRootsResponse { certificates }))
    } else {
        // No validator configured, return empty list
        Ok(Json(GetRootsResponse {
            certificates: vec![],
        }))
    }
}

pub async fn get_entry_and_proof(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<GetEntryAndProofRequest>,
) -> ApiResult<GetEntryAndProofResponse> {
    let tree_size = params.tree_size.unwrap_or({
        state
            .merkle_tree
            .size()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?
    });

    if params.leaf_index >= tree_size {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Leaf index out of bounds".to_string(),
            }),
        ));
    }

    let log_entry = state
        .storage
        .get_entry(params.leaf_index)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Log entry not found".to_string(),
                }),
            )
        })?;

    let chain_data = log_entry
        .chain
        .as_ref()
        .map(|c| c.clone())
        .unwrap_or_default();

    let leaf_input = log_entry
        .serialize()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())))?;

    let mut extra_data = Vec::new();
    match log_entry.entry_type {
        crate::types::LogEntryType::X509Entry => {
            // For X509ChainEntry, extra_data contains just the certificate_chain
            if !chain_data.is_empty() {
                // Calculate total chain length for TLS vector length prefix
                let mut total_chain_len = 0u32;
                for chain_cert in &chain_data {
                    total_chain_len += 3 + chain_cert.len() as u32; // 3-byte length + cert data
                }

                // TLS variable-length vector: chain length (3 bytes)
                extra_data.push((total_chain_len >> 16) as u8);
                extra_data.push((total_chain_len >> 8) as u8);
                extra_data.push(total_chain_len as u8);

                // Each certificate in the chain: length (3 bytes) + cert data
                for chain_cert in chain_data {
                    let cert_len = chain_cert.len() as u32;
                    extra_data.push((cert_len >> 16) as u8);
                    extra_data.push((cert_len >> 8) as u8);
                    extra_data.push(cert_len as u8);
                    extra_data.extend_from_slice(&chain_cert);
                }
            } else {
                // Empty chain: just the length field (0)
                extra_data.extend_from_slice(&[0x00, 0x00, 0x00]);
            }
        }
        crate::types::LogEntryType::PrecertEntry => {
            // For PrecertChainEntry, extra_data contains the whole PrecertChainEntry structure
            // struct { ASN.1Cert pre_certificate; ASN.1Cert precertificate_chain<0..2^24-1>; }

            // Pre_certificate length (3 bytes) + pre_certificate data (original, not TBS)
            if let Some(ref original_precert) = log_entry.original_precert {
                let precert_len = original_precert.len() as u32;
                extra_data.push((precert_len >> 16) as u8);
                extra_data.push((precert_len >> 8) as u8);
                extra_data.push(precert_len as u8);
                extra_data.extend_from_slice(original_precert);
            } else {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Missing original pre-certificate for PrecertEntry".to_string(),
                    }),
                ));
            }

            // Precertificate_chain (TLS variable-length vector)
            if !chain_data.is_empty() {
                // Calculate total chain length for TLS vector length prefix
                let mut total_chain_len = 0u32;
                for chain_cert in &chain_data {
                    total_chain_len += 3 + chain_cert.len() as u32; // 3-byte length + cert data
                }

                // TLS variable-length vector: chain length (3 bytes)
                extra_data.push((total_chain_len >> 16) as u8);
                extra_data.push((total_chain_len >> 8) as u8);
                extra_data.push(total_chain_len as u8);

                // Each certificate in the chain: length (3 bytes) + cert data
                for chain_cert in chain_data {
                    let cert_len = chain_cert.len() as u32;
                    extra_data.push((cert_len >> 16) as u8);
                    extra_data.push((cert_len >> 8) as u8);
                    extra_data.push(cert_len as u8);
                    extra_data.extend_from_slice(&chain_cert);
                }
            } else {
                // Empty chain: just the length field (0)
                extra_data.extend_from_slice(&[0x00, 0x00, 0x00]);
            }
        }
    }

    let proof = state
        .merkle_tree
        .prove_inclusion_efficient(tree_size, params.leaf_index)
        .await
        .map_err(|e| match e {
            crate::types::CtError::BadRequest(_) => (StatusCode::BAD_REQUEST, Json(e.into())),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(e.into())),
        })?;

    let response = GetEntryAndProofResponse {
        leaf_input: BASE64.encode(&leaf_input),
        extra_data: BASE64.encode(&extra_data),
        audit_path: serialization::inclusion_proof_to_audit_path(&proof),
    };

    Ok(Json(response))
}

#[derive(Serialize)]
pub struct GetRootsResponse {
    pub certificates: Vec<String>,
}

#[derive(Deserialize)]
pub struct GetEntryAndProofRequest {
    pub leaf_index: u64,
    pub tree_size: Option<u64>,
}

#[derive(Serialize)]
pub struct GetEntryAndProofResponse {
    pub leaf_input: String,
    pub extra_data: String,
    pub audit_path: Vec<String>,
}
