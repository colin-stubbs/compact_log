use axum::{
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::sync::Arc;

use crate::{
    merkle_storage::StorageBackedMerkleTree,
    storage::CtStorage,
    types::{sct::SctBuilder, tree_head::SthBuilder, LogId},
    validation::Rfc6962Validator,
};

pub mod handlers;

pub struct ApiState {
    pub storage: Arc<CtStorage>,
    pub merkle_tree: StorageBackedMerkleTree,
    pub sct_builder: Arc<SctBuilder>,
    pub sth_builder: Arc<SthBuilder>,
    pub validator: Option<Arc<Rfc6962Validator>>,
    pub log_id: LogId,
    pub public_key_der: Vec<u8>,
    pub base_url: String,
}

impl ApiState {
    pub fn new(
        storage: Arc<CtStorage>,
        merkle_tree: StorageBackedMerkleTree,
        log_id: LogId,
        private_key: Vec<u8>,
        public_key_der: Vec<u8>,
        base_url: String,
        validator: Option<Arc<Rfc6962Validator>>,
    ) -> crate::types::Result<Self> {
        let sct_builder = Arc::new(SctBuilder::from_private_key_bytes(
            log_id.clone(),
            &private_key,
        )?);
        let sth_builder = Arc::new(SthBuilder::from_private_key_bytes(&private_key)?);

        Ok(Self {
            storage,
            merkle_tree,
            sct_builder,
            sth_builder,
            validator,
            log_id,
            public_key_der,
            base_url,
        })
    }
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/ct/v1/add-chain", post(handlers::add_chain))
        .route("/ct/v1/add-pre-chain", post(handlers::add_pre_chain))
        .route("/ct/v1/get-sth", get(handlers::get_sth))
        .route(
            "/ct/v1/get-sth-consistency",
            get(handlers::get_sth_consistency),
        )
        .route("/ct/v1/get-proof-by-hash", get(handlers::get_proof_by_hash))
        .route("/ct/v1/get-entries", get(handlers::get_entries))
        .route("/ct/v1/get-roots", get(handlers::get_roots))
        .route(
            "/ct/v1/get-entry-and-proof",
            get(handlers::get_entry_and_proof),
        )
        // Inclusion request endpoint
        .route("/inclusion_request.json", get(handlers::inclusion_request))
        // Health check
        .route("/health", get(health_check))
        .with_state(Arc::new(state))
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl From<crate::types::CtError> for ErrorResponse {
    fn from(err: crate::types::CtError) -> Self {
        Self {
            error: err.to_string(),
        }
    }
}

impl From<crate::storage::StorageError> for ErrorResponse {
    fn from(err: crate::storage::StorageError) -> Self {
        Self {
            error: format!("Storage error: {}", err),
        }
    }
}
