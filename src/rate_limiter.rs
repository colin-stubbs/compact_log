use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct ReadRateLimiter {
    semaphore: Arc<Semaphore>,
    warmup_start: Instant,
    warmup_end: Instant,
    last_log: Arc<AtomicU64>,
}

impl ReadRateLimiter {
    pub fn new(max_concurrent_reads: usize, warmup_duration_secs: u64) -> Self {
        tracing::info!(
            "Starting cache warmup period for {} seconds with {} max concurrent reads",
            warmup_duration_secs,
            max_concurrent_reads
        );

        let now = Instant::now();
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent_reads)),
            warmup_start: now,
            warmup_end: now + Duration::from_secs(warmup_duration_secs),
            last_log: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn acquire(&self) -> Option<ReadPermit> {
        let now = Instant::now();

        if now >= self.warmup_end {
            // Log once when warmup ends
            let was_active = self.last_log.swap(u64::MAX, Ordering::Relaxed);
            if was_active != u64::MAX {
                tracing::info!("Cache warmup period ended - rate limiting disabled");
            }
            return None;
        }

        // Log remaining time every 10 seconds
        let elapsed_secs = now.duration_since(self.warmup_start).as_secs();
        let last_log_secs = self.last_log.load(Ordering::Relaxed);

        if elapsed_secs >= last_log_secs + 10 {
            let remaining = (self.warmup_end - now).as_secs();
            tracing::info!("Cache warmup period ends in {} seconds", remaining);
            self.last_log.store(elapsed_secs, Ordering::Relaxed);
        }

        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        Some(ReadPermit { _permit: permit })
    }
}

pub struct ReadPermit {
    _permit: OwnedSemaphorePermit,
}
