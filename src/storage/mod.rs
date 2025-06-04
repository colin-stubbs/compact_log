use crate::merkle_storage::StorageBackedMerkleTree;
use crate::types::{sct::SignedCertificateTimestamp, LogEntry};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use slatedb::Db;
use std::sync::{atomic::AtomicU64, atomic::Ordering, Arc};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Mutex};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("SlateDB error: {0}")]
    SlateDb(slatedb::SlateDBError),

    #[error("Invalid data format: {0}")]
    InvalidFormat(String),
}

impl Clone for StorageError {
    fn clone(&self) -> Self {
        match self {
            StorageError::SlateDb(_) => {
                StorageError::InvalidFormat("SlateDB error during batch processing".to_string())
            }
            StorageError::InvalidFormat(s) => StorageError::InvalidFormat(s.clone()),
        }
    }
}

impl From<slatedb::SlateDBError> for StorageError {
    fn from(e: slatedb::SlateDBError) -> Self {
        StorageError::SlateDb(e)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Entry to be batched and flushed
#[derive(Debug)]
pub struct BatchEntry {
    pub index: u64,
    pub log_entry: LogEntry,
    pub cert_hash: [u8; 32],
    pub sct: SignedCertificateTimestamp,
    pub completion_tx: oneshot::Sender<Result<()>>,
}

/// Certificate SCT mapping entry for deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSctEntry {
    pub index: u64,
    pub sct: SignedCertificateTimestamp,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of entries to batch before flushing
    pub max_batch_size: usize,
    /// Maximum time to wait before flushing (in milliseconds)
    pub max_batch_timeout_ms: u64,
}

pub struct KeyPrefix;

impl KeyPrefix {
    /// Log entries
    pub const ENTRY: &'static str = "entry:";

    /// Hash to index mapping for efficient proof-by-hash lookups
    pub const HASH_INDEX: &'static str = "hash:";

    /// Certificate hash to SCT mapping for deduplication
    pub const CERT_SCT: &'static str = "cert_sct:";
}

/// Storage backend for Certificate Transparency log using SlateDB with batching
pub struct CtStorage {
    pub(crate) db: Arc<Db>,
    next_index: Arc<AtomicU64>,
    batch_sender: mpsc::UnboundedSender<BatchEntry>,
}

impl BatchConfig {
    pub fn default() -> Self {
        Self {
            max_batch_size: 10_000,
            max_batch_timeout_ms: 500,
        }
    }
}

impl CtStorage {
    pub async fn new(
        db: Arc<Db>,
        config: BatchConfig,
        merkle_tree: Arc<tokio::sync::RwLock<StorageBackedMerkleTree>>,
    ) -> Result<Self> {
        let tree = merkle_tree.read().await;
        let initial_tree_size = tree.size().await.map_err(|e| {
            StorageError::InvalidFormat(format!("Failed to get tree size: {:?}", e))
        })?;
        drop(tree);

        let next_index = Arc::new(AtomicU64::new(initial_tree_size));
        let (batch_sender, batch_receiver) = mpsc::unbounded_channel();
        let batch_mutex = Arc::new(Mutex::new(()));

        let mutex_clone = batch_mutex.clone();
        let tree_clone = merkle_tree.clone();
        tokio::spawn(async move {
            Self::batch_worker(batch_receiver, config, mutex_clone, tree_clone).await;
        });

        Ok(Self {
            db,
            next_index,
            batch_sender,
        })
    }

    /// Add entry to batch queue and return assigned index
    pub async fn add_entry_batched(
        &self,
        log_entry: LogEntry,
        cert_hash: [u8; 32],
        sct: SignedCertificateTimestamp,
    ) -> Result<u64> {
        tracing::debug!("add_entry_batched: Starting");

        let index = self.next_index.fetch_add(1, Ordering::SeqCst);

        tracing::debug!("add_entry_batched: Assigned index {}", index);

        let (completion_tx, completion_rx) = oneshot::channel();

        let batch_entry = BatchEntry {
            index,
            log_entry,
            cert_hash,
            sct,
            completion_tx,
        };

        if self.batch_sender.send(batch_entry).is_err() {
            tracing::error!("add_entry_batched: Failed to send to batch worker");
            return Err(StorageError::InvalidFormat(
                "Batch worker not running".into(),
            ));
        }

        tracing::debug!("add_entry_batched: Sent to batch worker, waiting for completion");

        let result = completion_rx.await.map_err(|_| {
            tracing::error!("add_entry_batched: Completion channel closed");
            StorageError::InvalidFormat("Batch completion channel closed".into())
        })?;

        tracing::debug!("add_entry_batched: Received completion result");
        result.map(|_| index)
    }

    /// Background worker that batches and flushes entries
    async fn batch_worker(
        mut batch_receiver: mpsc::UnboundedReceiver<BatchEntry>,
        config: BatchConfig,
        batch_mutex: Arc<Mutex<()>>,
        merkle_tree: Arc<tokio::sync::RwLock<StorageBackedMerkleTree>>,
    ) {
        tracing::info!("batch_worker: Starting background worker");
        let mut pending_entries = Vec::with_capacity(config.max_batch_size);
        let timeout_duration = std::time::Duration::from_millis(config.max_batch_timeout_ms);
        let mut timeout = Box::pin(tokio::time::sleep(timeout_duration));

        loop {
            tokio::select! {
                entry = batch_receiver.recv() => {
                    match entry {
                        Some(entry) => {
                            let was_empty = pending_entries.is_empty();
                            tracing::debug!("batch_worker: Received entry with index {}", entry.index);
                            pending_entries.push(entry);

                            // If this is the first entry in the batch, reset the timeout
                            if was_empty {
                                timeout.as_mut().reset(tokio::time::Instant::now() + timeout_duration);
                            }

                            if pending_entries.len() >= config.max_batch_size {
                                tracing::debug!("batch_worker: Batch full, flushing {} entries", pending_entries.len());
                                Self::flush_batch(&mut pending_entries, &batch_mutex, &merkle_tree).await;
                                // Reset timeout for next batch
                                timeout.as_mut().reset(tokio::time::Instant::now() + timeout_duration);
                            }
                        }
                        None => {
                            if !pending_entries.is_empty() {
                                tracing::debug!("batch_worker: Channel closed, flushing {} remaining entries", pending_entries.len());
                                Self::flush_batch(&mut pending_entries, &batch_mutex, &merkle_tree).await;
                            }
                            tracing::info!("batch_worker: Exiting");
                            break;
                        }
                    }
                }

                // Timeout: flush pending entries
                _ = &mut timeout => {
                    if !pending_entries.is_empty() {
                        tracing::debug!("batch_worker: Timeout reached, flushing {} entries", pending_entries.len());
                        Self::flush_batch(&mut pending_entries, &batch_mutex, &merkle_tree).await;
                    }
                    // Reset timeout for next batch
                    timeout.as_mut().reset(tokio::time::Instant::now() + timeout_duration);
                }
            }
        }
    }

    /// Flush a batch of entries atomically
    async fn flush_batch(
        entries: &mut Vec<BatchEntry>,
        batch_mutex: &Arc<Mutex<()>>,
        merkle_tree: &Arc<tokio::sync::RwLock<StorageBackedMerkleTree>>,
    ) {
        if entries.is_empty() {
            tracing::debug!("flush_batch: No entries to flush");
            return;
        }

        let _lock = batch_mutex.lock().await;

        tracing::debug!("flush_batch: Flushing {} entries", entries.len());

        let mut additional_data = Vec::new();
        let mut leaf_data_vec = Vec::new();
        let mut failed_entries = Vec::new();

        for (i, entry) in entries.iter().enumerate() {
            let entry_key = format!("{}:{}", KeyPrefix::ENTRY, entry.index);
            let entry_data = match entry.log_entry.serialize_for_storage() {
                Ok(data) => data,
                Err(e) => {
                    failed_entries.push((i, Err(StorageError::InvalidFormat(e.to_string()))));
                    continue;
                }
            };

            // For get-proof-by-hash API, we need to store hash->index mapping
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&[0x00]); // Leaf prefix
            hasher.update(&entry.log_entry.leaf_data);
            let computed_leaf_hash: [u8; 32] = hasher.finalize().into();

            let hash_key = format!(
                "{}:{}",
                KeyPrefix::HASH_INDEX,
                hex::encode(&computed_leaf_hash)
            );

            let cert_sct_key = format!("{}:{}", KeyPrefix::CERT_SCT, hex::encode(&entry.cert_hash));
            let sct_entry = CertificateSctEntry {
                index: entry.index,
                sct: entry.sct.clone(),
                timestamp: entry.sct.timestamp,
            };
            let sct_data =
                match bincode::serde::encode_to_vec(&sct_entry, bincode::config::standard()) {
                    Ok(data) => data,
                    Err(e) => {
                        failed_entries.push((
                            i,
                            Err(StorageError::InvalidFormat(format!(
                                "Failed to serialize SCT entry: {}",
                                e
                            ))),
                        ));
                        continue;
                    }
                };

            additional_data.push((entry_key.into_bytes(), entry_data));
            additional_data.push((hash_key.into_bytes(), entry.index.to_be_bytes().to_vec()));
            additional_data.push((cert_sct_key.into_bytes(), sct_data));

            leaf_data_vec.push(entry.log_entry.leaf_data.clone());
        }

        let final_result = if !leaf_data_vec.is_empty() || !additional_data.is_empty() {
            tracing::debug!(
                "flush_batch: Pushing {} entries with {} additional writes to merkle tree",
                leaf_data_vec.len(),
                additional_data.len()
            );
            let tree = merkle_tree.read().await;
            tree.batch_push_with_data(leaf_data_vec, additional_data)
                .await
                .map_err(|e| StorageError::InvalidFormat(format!("Merkle tree error: {:?}", e)))
        } else {
            Ok(())
        };

        tracing::debug!(
            "flush_batch: Completed with result: {:?}",
            final_result.is_ok()
        );

        // Notify all entries in batch
        for (i, entry) in entries.drain(..).enumerate() {
            if let Some((_, error)) = failed_entries.iter().find(|(idx, _)| *idx == i) {
                tracing::info!(
                    "flush_batch: Notifying entry {} with serialization error",
                    i
                );
                let _ = entry.completion_tx.send(error.clone());
            } else {
                tracing::debug!("flush_batch: Notifying entry {} with final result", i);
                let _ = entry.completion_tx.send(final_result.clone());
            }
        }

        tracing::debug!("flush_batch: All entries notified");
    }

    pub async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        Ok(self.db.get(key.as_bytes()).await?)
    }

    /// Find index by hash
    pub async fn find_index_by_hash(&self, hash: &[u8]) -> Result<Option<u64>> {
        let hash_key = format!("{}:{}", KeyPrefix::HASH_INDEX, hex::encode(hash));
        match self.get(&hash_key).await? {
            Some(bytes) => {
                let index_array: [u8; 8] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| StorageError::InvalidFormat("Invalid index format".into()))?;
                Ok(Some(u64::from_be_bytes(index_array)))
            }
            None => Ok(None),
        }
    }

    /// Get SCT by certificate hash for deduplication
    pub async fn get_sct_by_cert_hash(
        &self,
        cert_hash: &[u8; 32],
    ) -> Result<Option<CertificateSctEntry>> {
        let key = format!("{}:{}", KeyPrefix::CERT_SCT, hex::encode(cert_hash));
        match self.get(&key).await? {
            Some(bytes) => {
                let entry: CertificateSctEntry =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                        .map(|(entry, _)| entry)
                        .map_err(|e| {
                            StorageError::InvalidFormat(format!(
                                "Failed to deserialize SCT entry: {}",
                                e
                            ))
                        })?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }
}
