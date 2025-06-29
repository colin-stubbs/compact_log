use crate::rate_limiter::{ReadPermit, ReadRateLimiter};
use bytes::Bytes;
use slatedb::{Db, WriteBatch};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A wrapper around SlateDB that enforces rate limiting on read operations
#[derive(Clone)]
pub struct RateLimitedDb {
    db: Arc<Db>,
    read_rate_limiter: Option<ReadRateLimiter>,
    read_ops: Arc<AtomicU64>,
    bytes_read: Arc<AtomicU64>,
}

impl RateLimitedDb {
    /// Create a new RateLimitedDb with optional rate limiting
    pub fn new(db: Arc<Db>, read_rate_limiter: Option<ReadRateLimiter>) -> Self {
        Self {
            db,
            read_rate_limiter,
            read_ops: Arc::new(AtomicU64::new(0)),
            bytes_read: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get a value from the database, potentially rate limited
    pub async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, slatedb::SlateDBError> {
        let _permit: Option<ReadPermit> = if let Some(ref limiter) = self.read_rate_limiter {
            limiter.acquire().await
        } else {
            None
        };

        self.read_ops.fetch_add(1, Ordering::Relaxed);

        let result = self.db.get(key).await?;

        if let Some(ref value) = result {
            self.bytes_read
                .fetch_add(value.len() as u64, Ordering::Relaxed);
        }

        Ok(result)
    }

    /// Put a value into the database (not rate limited)
    pub async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), slatedb::SlateDBError> {
        self.db.put(key, value).await
    }

    /// Write a batch of operations (not rate limited)
    pub async fn write_batch(&self, batch: WriteBatch) -> Result<(), slatedb::SlateDBError> {
        self.db.write(batch).await
    }

    pub fn get_read_stats(&self) -> (u64, u64) {
        (
            self.read_ops.load(Ordering::Relaxed),
            self.bytes_read.load(Ordering::Relaxed),
        )
    }
}
