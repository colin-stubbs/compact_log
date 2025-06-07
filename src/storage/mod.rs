use crate::merkle_storage::StorageBackedMerkleTree;
use crate::types::{sct::SignedCertificateTimestamp, LogEntry};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use slatedb::Db;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Mutex};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("SlateDB error: {0}")]
    SlateDb(slatedb::SlateDBError),

    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    #[error("Queue full - system at capacity")]
    QueueFull,
}

impl Clone for StorageError {
    fn clone(&self) -> Self {
        match self {
            StorageError::SlateDb(_) => {
                StorageError::InvalidFormat("SlateDB error during batch processing".to_string())
            }
            StorageError::InvalidFormat(s) => StorageError::InvalidFormat(s.clone()),
            StorageError::QueueFull => StorageError::QueueFull,
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
    pub log_entry: LogEntry,
    pub cert_hash: [u8; 32],
    pub sct: SignedCertificateTimestamp,
    pub completion_tx: oneshot::Sender<Result<u64>>,
}

/// Certificate SCT mapping entry for deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSctEntry {
    pub index: u64,
    pub sct: SignedCertificateTimestamp,
    pub timestamp: u64,
}


/// Statistics for batch processing
#[derive(Debug, Default)]
struct BatchStats {
    batches_flushed: u64,
    total_entries: u64,
    total_flush_time_ms: u64,
    min_batch_size: usize,
    max_batch_size: usize,
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
    batch_sender: mpsc::Sender<BatchEntry>,
}

impl BatchConfig {
    pub fn default() -> Self {
        Self {
            max_batch_size: 500,
            max_batch_timeout_ms: 500,
        }
    }
}

impl CtStorage {
    pub async fn new(
        db: Arc<Db>,
        config: BatchConfig,
        merkle_tree: StorageBackedMerkleTree,
    ) -> Result<Self> {
        // Use a bounded channel to provide backpressure
        let channel_capacity = (config.max_batch_size * 2).max(500);
        let (batch_sender, batch_receiver) = mpsc::channel(channel_capacity);
        let batch_mutex = Arc::new(Mutex::new(()));

        let mutex_clone = batch_mutex.clone();
        let tree_clone = merkle_tree.clone();
        let batch_stats = Arc::new(Mutex::new(BatchStats::default()));
        let stats_clone = batch_stats.clone();

        tokio::spawn(async move {
            Self::batch_worker(batch_receiver, config, mutex_clone, tree_clone, stats_clone).await;
        });


        // Start metrics logging task
        let metrics_sender = batch_sender.clone();
        let metrics_stats = batch_stats.clone();
        tokio::spawn(async move {
            Self::metrics_worker(metrics_sender, metrics_stats).await;
        });

        Ok(Self {
            db,
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
        let (completion_tx, completion_rx) = oneshot::channel();

        let batch_entry = BatchEntry {
            log_entry,
            cert_hash,
            sct,
            completion_tx,
        };

        match self.batch_sender.try_send(batch_entry) {
            Ok(_) => {
                tracing::trace!(
                    "add_entry_batched: Added entry to batch queue, current depth: {}/{}",
                    self.batch_sender.capacity(),
                    self.batch_sender.max_capacity()
                );
            }
            Err(e) => match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(
                        "add_entry_batched: Batch queue is full at capacity {}",
                        self.batch_sender.max_capacity()
                    );
                    return Err(StorageError::QueueFull);
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("add_entry_batched: Batch worker not running");
                    return Err(StorageError::InvalidFormat(
                        "Batch worker not running".into(),
                    ));
                }
            },
        }

        let index = completion_rx.await.map_err(|_| {
            tracing::error!("add_entry_batched: Completion channel closed");
            StorageError::InvalidFormat("Batch completion channel closed".into())
        })?;

        match index {
            Ok(idx) => {
                tracing::trace!(
                    "add_entry_batched: Received completion result with index {}",
                    idx
                );
                Ok(idx)
            }
            Err(e) => {
                tracing::error!("add_entry_batched: Received completion error");
                Err(e)
            }
        }
    }

    /// Background worker that batches and flushes entries
    async fn batch_worker(
        mut batch_receiver: mpsc::Receiver<BatchEntry>,
        config: BatchConfig,
        batch_mutex: Arc<Mutex<()>>,
        merkle_tree: StorageBackedMerkleTree,
        batch_stats: Arc<Mutex<BatchStats>>,
    ) {
        tracing::trace!("batch_worker: Starting background worker");
        let mut pending_entries = Vec::with_capacity(config.max_batch_size);
        let timeout_duration = std::time::Duration::from_millis(config.max_batch_timeout_ms);

        let mut interval = tokio::time::interval(timeout_duration);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                entry = batch_receiver.recv() => {
                    match entry {
                        Some(entry) => {
                            tracing::debug!("batch_worker: Received entry");
                            pending_entries.push(entry);

                            // After receiving one entry, try to drain more without blocking
                            while pending_entries.len() < config.max_batch_size {
                                match batch_receiver.try_recv() {
                                    Ok(entry) => {
                                        pending_entries.push(entry);
                                    }
                                    Err(_) => break, // Channel empty or closed
                                }
                            }

                            if pending_entries.len() >= config.max_batch_size {
                                tracing::trace!("batch_worker: Batch full ({}), flushing {} entries", config.max_batch_size, pending_entries.len());
                                Self::flush_batch(&mut pending_entries, batch_mutex.clone(), merkle_tree.clone(), batch_stats.clone()).await;
                            }
                        }
                        None => {
                            if !pending_entries.is_empty() {
                                tracing::trace!("batch_worker: Channel closed, flushing {} remaining entries", pending_entries.len());
                                Self::flush_batch(&mut pending_entries, batch_mutex.clone(), merkle_tree.clone(), batch_stats.clone()).await;
                            }
                            tracing::info!("batch_worker: Exiting");
                            break;
                        }
                    }
                }

                _ = interval.tick() => {
                    // Time-based flush
                    if !pending_entries.is_empty() {
                        let time = Instant::now();
                        tracing::trace!("batch_worker: Time flush after {}ms, flushing {} entries",
                            timeout_duration.as_millis(), pending_entries.len());
                        Self::flush_batch(&mut pending_entries, batch_mutex.clone(), merkle_tree.clone(), batch_stats.clone()).await;
                        tracing::trace!("batch_worker: Flushed in {}ms", time.elapsed().as_millis());
                    }
                }
            }
        }
    }

    /// Flush a batch of entries atomically
    async fn flush_batch(
        entries: &mut Vec<BatchEntry>,
        batch_mutex: Arc<Mutex<()>>,
        merkle_tree: StorageBackedMerkleTree,
        batch_stats: Arc<Mutex<BatchStats>>,
    ) {
        if entries.is_empty() {
            tracing::trace!("flush_batch: No entries to flush");
            return;
        }

        let _lock = batch_mutex.lock().await;
        let start_time = Instant::now();
        let batch_size = entries.len();

        tracing::trace!("flush_batch: Flushing {} entries", batch_size);

        let mut leaf_data_vec = Vec::new();
        let mut entry_metadata = Vec::new();
        let mut failed_entries = Vec::new();

        tracing::trace!(
            "Elapsed time before processing entries: {:?}",
            start_time.elapsed()
        );
        for (i, entry) in entries.iter().enumerate() {
            match entry.log_entry.serialize_for_storage() {
                Ok(entry_data) => {
                    entry_metadata.push((
                        i,
                        entry_data,
                        entry.cert_hash.clone(),
                        entry.sct.clone(),
                    ));
                    leaf_data_vec.push(entry.log_entry.leaf_data.clone());
                }
                Err(e) => {
                    failed_entries.push((i, StorageError::InvalidFormat(e.to_string())));
                }
            }
        }
        tracing::trace!(
            "Elapsed time after processing entries: {:?}",
            start_time.elapsed(),
        );

        let push_result = if !leaf_data_vec.is_empty() {
            tracing::trace!(
                "flush_batch: Pushing {} entries to merkle tree",
                leaf_data_vec.len()
            );

            // Build the additional data that needs to be written atomically with the tree
            let starting_index =
                match merkle_tree.size().await {
                    Ok(size) => size,
                    Err(e) => {
                        tracing::error!("Failed to get tree size: {:?}", e);
                        for entry in entries.drain(..) {
                            let _ = entry.completion_tx.send(Err(StorageError::InvalidFormat(
                                format!("Failed to get tree size: {:?}", e),
                            )));
                        }
                        return;
                    }
                };

            // Prepare all additional data with correct indices
            let mut additional_data = Vec::new();
            for (vec_idx, (_orig_idx, entry_data, cert_hash, sct)) in
                entry_metadata.iter().enumerate()
            {
                let index = starting_index + vec_idx as u64;

                let entry_key = format!("{}:{}", KeyPrefix::ENTRY, index);

                // For get-proof-by-hash API, we need to store hash->index mapping
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&[0x00]); // Leaf prefix
                hasher.update(&leaf_data_vec[vec_idx]);
                let computed_leaf_hash: [u8; 32] = hasher.finalize().into();

                let hash_key = format!(
                    "{}:{}",
                    KeyPrefix::HASH_INDEX,
                    hex::encode(&computed_leaf_hash)
                );

                let cert_sct_key = format!("{}:{}", KeyPrefix::CERT_SCT, hex::encode(cert_hash));
                let sct_entry = CertificateSctEntry {
                    index,
                    sct: sct.clone(),
                    timestamp: sct.timestamp,
                };
                let sct_data =
                    match bincode::serde::encode_to_vec(&sct_entry, bincode::config::standard()) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::error!("Failed to serialize SCT entry: {}", e);
                            continue;
                        }
                    };

                additional_data.push((entry_key.into_bytes(), entry_data.clone()));
                additional_data.push((hash_key.into_bytes(), index.to_be_bytes().to_vec()));
                additional_data.push((cert_sct_key.into_bytes(), sct_data));
            }

            tracing::trace!("Elapsed time before batch push: {:?}", start_time.elapsed());
            match merkle_tree
                .batch_push_with_data(leaf_data_vec, additional_data)
                .await
            {
                Ok(actual_starting_index) => {
                    // Sanity check
                    if actual_starting_index != starting_index {
                        tracing::error!(
                            "Index mismatch: expected {}, got {}",
                            starting_index,
                            actual_starting_index
                        );
                    }
                    Ok(actual_starting_index)
                }
                Err(e) => Err(StorageError::InvalidFormat(format!(
                    "Merkle tree error: {:?}",
                    e
                ))),
            }
        } else {
            Err(StorageError::InvalidFormat(
                "No valid entries to flush".into(),
            ))
        };
        tracing::trace!("Elapsed time after batch push: {:?}", start_time.elapsed());

        tracing::trace!(
            "flush_batch: Completed with result: {:?}",
            push_result.is_ok()
        );

        // Notify all entries with their results
        match push_result {
            Ok(starting_index) => {
                let mut valid_idx = 0;
                for (i, entry) in entries.drain(..).enumerate() {
                    if let Some((_, error)) = failed_entries.iter().find(|(idx, _)| *idx == i) {
                        tracing::info!(
                            "flush_batch: Notifying entry {} with serialization error",
                            i
                        );
                        let _ = entry.completion_tx.send(Err(error.clone()));
                    } else {
                        let assigned_index = starting_index + valid_idx;
                        valid_idx += 1;
                        tracing::trace!(
                            "flush_batch: Notifying entry {} with assigned index {}",
                            i,
                            assigned_index
                        );
                        let _ = entry.completion_tx.send(Ok(assigned_index));
                    }
                }
            }
            Err(e) => {
                for (i, entry) in entries.drain(..).enumerate() {
                    if let Some((_, error)) = failed_entries.iter().find(|(idx, _)| *idx == i) {
                        let _ = entry.completion_tx.send(Err(error.clone()));
                    } else {
                        let _ = entry.completion_tx.send(Err(e.clone()));
                    }
                }
            }
        }

        tracing::trace!(
            "Elapsed time after notifying entries: {:?}",
            start_time.elapsed()
        );

        // Record batch statistics
        let flush_time_ms = start_time.elapsed().as_millis() as u64;
        let mut stats = batch_stats.lock().await;
        stats.batches_flushed += 1;
        stats.total_entries += batch_size as u64;
        stats.total_flush_time_ms += flush_time_ms;

        if stats.min_batch_size == 0 || batch_size < stats.min_batch_size {
            stats.min_batch_size = batch_size;
        }
        if batch_size > stats.max_batch_size {
            stats.max_batch_size = batch_size;
        }

        tracing::trace!(
            "flush_batch: Flushed {} entries in {}ms (total batches: {}, total time: {}ms)",
            batch_size,
            flush_time_ms,
            stats.batches_flushed,
            stats.total_flush_time_ms
        );
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


    /// Background worker that logs queue metrics periodically
    async fn metrics_worker(
        batch_sender: mpsc::Sender<BatchEntry>,
        batch_stats: Arc<Mutex<BatchStats>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut last_stats = BatchStats::default();

        loop {
            interval.tick().await;

            // Get current queue depth
            let capacity = batch_sender.capacity();
            let max_capacity = batch_sender.max_capacity();
            let current_depth = max_capacity - capacity;
            let utilization_percent = (current_depth as f64 / max_capacity as f64) * 100.0;

            // Get batch statistics
            let stats = batch_stats.lock().await;
            let interval_batches = stats
                .batches_flushed
                .saturating_sub(last_stats.batches_flushed);
            let interval_entries = stats.total_entries.saturating_sub(last_stats.total_entries);
            let interval_time_ms = stats
                .total_flush_time_ms
                .saturating_sub(last_stats.total_flush_time_ms);

            if interval_batches > 0 {
                let avg_batch_size = interval_entries / interval_batches;
                let avg_flush_time = interval_time_ms / interval_batches;
                let throughput = (interval_entries as f64 / 5.0) as u64; // entries per second

                tracing::info!(
                    "Batch stats: {} batches flushed (avg size: {}, avg time: {}ms), throughput: {} entries/sec, queue: {}/{}",
                    interval_batches,
                    avg_batch_size,
                    avg_flush_time,
                    throughput,
                    current_depth,
                    max_capacity
                );
            } else {
                tracing::info!(
                    "Batch stats: No batches flushed in last 5s, queue: {}/{}",
                    current_depth,
                    max_capacity
                );
            }

            // Clone current stats for next interval
            last_stats = BatchStats {
                batches_flushed: stats.batches_flushed,
                total_entries: stats.total_entries,
                total_flush_time_ms: stats.total_flush_time_ms,
                min_batch_size: stats.min_batch_size,
                max_batch_size: stats.max_batch_size,
            };
            drop(stats);

            // Still warn about queue depth
            if utilization_percent > 90.0 {
                tracing::warn!(
                    "Queue utilization critical: {}%",
                    utilization_percent as u32
                );
            } else if utilization_percent > 75.0 {
                tracing::warn!("Queue utilization high: {}%", utilization_percent as u32);
            }
        }
    }

}
