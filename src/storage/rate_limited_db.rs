use crate::rate_limiter::{ReadPermit, ReadRateLimiter};
use bytes::Bytes;
use slatedb::{Db, WriteBatch};
use std::sync::Arc;

/// A wrapper around SlateDB that enforces rate limiting on read operations
#[derive(Clone)]
pub struct RateLimitedDb {
    db: Arc<Db>,
    read_rate_limiter: Option<ReadRateLimiter>,
}

impl RateLimitedDb {
    /// Create a new RateLimitedDb with optional rate limiting
    pub fn new(db: Arc<Db>, read_rate_limiter: Option<ReadRateLimiter>) -> Self {
        Self {
            db,
            read_rate_limiter,
        }
    }

    /// Get a value from the database, potentially rate limited
    pub async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, slatedb::SlateDBError> {
        // Acquire rate limit permit if rate limiter is configured
        let _permit: Option<ReadPermit> = if let Some(ref limiter) = self.read_rate_limiter {
            limiter.acquire().await
        } else {
            None
        };

        // Perform the actual read
        self.db.get(key).await
    }

    /// Put a value into the database (not rate limited)
    pub async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), slatedb::SlateDBError> {
        self.db.put(key, value).await
    }

    /// Write a batch of operations (not rate limited)
    pub async fn write_batch(&self, batch: WriteBatch) -> Result<(), slatedb::SlateDBError> {
        self.db.write(batch).await
    }
}
