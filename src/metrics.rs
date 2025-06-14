use lazy_static::lazy_static;
use prometheus::{
    register_gauge, register_gauge_vec, register_histogram_vec, register_int_counter_vec,
    register_int_gauge, Gauge, GaugeVec, HistogramVec, IntCounterVec, IntGauge,
};

lazy_static! {
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["endpoint", "method", "status"]
    )
    .unwrap();
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["endpoint", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();
    pub static ref CERTIFICATE_SUBMISSIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "certificate_submissions_total",
        "Total number of certificate submissions",
        &["type", "status"]
    )
    .unwrap();
    pub static ref STORAGE_QUEUE_DEPTH: IntGauge =
        register_int_gauge!("storage_queue_depth", "Current depth of the storage queue").unwrap();
    pub static ref STORAGE_QUEUE_CAPACITY: IntGauge = register_int_gauge!(
        "storage_queue_capacity",
        "Maximum capacity of the storage queue"
    )
    .unwrap();
    pub static ref STORAGE_BATCHES_FLUSHED: IntCounterVec = register_int_counter_vec!(
        "storage_batches_flushed_total",
        "Total number of storage batches flushed",
        &["status"]
    )
    .unwrap();
    pub static ref STORAGE_ENTRIES_PROCESSED: IntCounterVec = register_int_counter_vec!(
        "storage_entries_processed_total",
        "Total number of entries processed by storage",
        &["type"]
    )
    .unwrap();
    pub static ref STORAGE_FLUSH_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "storage_flush_duration_seconds",
        "Duration of storage flush operations in seconds",
        &["status"],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();
    pub static ref MERKLE_TREE_SIZE: IntGauge = register_int_gauge!(
        "merkle_tree_size",
        "Current size of the Merkle tree (number of entries)"
    )
    .unwrap();
    pub static ref DEDUPLICATED_CERTIFICATES: IntCounterVec = register_int_counter_vec!(
        "deduplicated_certificates_total",
        "Total number of deduplicated certificates",
        &["type"]
    )
    .unwrap();
    pub static ref CACHE_HITS: IntCounterVec = register_int_counter_vec!(
        "cache_hits_total",
        "Total number of cache hits",
        &["cache_type"]
    )
    .unwrap();
    pub static ref CACHE_MISSES: IntCounterVec = register_int_counter_vec!(
        "cache_misses_total",
        "Total number of cache misses",
        &["cache_type"]
    )
    .unwrap();
    pub static ref ACTIVE_CONNECTIONS: Gauge =
        register_gauge!("active_connections", "Number of active HTTP connections").unwrap();
    pub static ref CERTIFICATE_CHAIN_LENGTH: HistogramVec = register_histogram_vec!(
        "certificate_chain_length",
        "Length of certificate chains submitted",
        &["type"],
        vec![1.0, 2.0, 3.0, 4.0, 5.0, 10.0]
    )
    .unwrap();
    pub static ref VALIDATION_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "validation_duration_seconds",
        "Duration of certificate validation in seconds",
        &["type"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap();
    pub static ref GET_ENTRIES_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "get_entries_requests_total",
        "Total number of get-entries requests",
        &["status"]
    )
    .unwrap();
    pub static ref GET_ENTRIES_BATCH_SIZE: HistogramVec = register_histogram_vec!(
        "get_entries_batch_size",
        "Number of entries requested in get-entries calls",
        &[],
        vec![1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
    )
    .unwrap();
    pub static ref INCLUSION_PROOF_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "inclusion_proof_requests_total",
        "Total number of inclusion proof requests",
        &["status"]
    )
    .unwrap();
    pub static ref CONSISTENCY_PROOF_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "consistency_proof_requests_total",
        "Total number of consistency proof requests",
        &["status"]
    )
    .unwrap();
    pub static ref HEALTH_CHECK_STATUS: GaugeVec = register_gauge_vec!(
        "health_check_status",
        "Health check status (1 = healthy, 0 = unhealthy)",
        &["component"]
    )
    .unwrap();
}

pub fn init_metrics() {
    lazy_static::initialize(&HTTP_REQUESTS_TOTAL);
    lazy_static::initialize(&HTTP_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&CERTIFICATE_SUBMISSIONS_TOTAL);
    lazy_static::initialize(&STORAGE_QUEUE_DEPTH);
    lazy_static::initialize(&STORAGE_QUEUE_CAPACITY);
    lazy_static::initialize(&STORAGE_BATCHES_FLUSHED);
    lazy_static::initialize(&STORAGE_ENTRIES_PROCESSED);
    lazy_static::initialize(&STORAGE_FLUSH_DURATION_SECONDS);
    lazy_static::initialize(&MERKLE_TREE_SIZE);
    lazy_static::initialize(&DEDUPLICATED_CERTIFICATES);
    lazy_static::initialize(&CACHE_HITS);
    lazy_static::initialize(&CACHE_MISSES);
    lazy_static::initialize(&ACTIVE_CONNECTIONS);
    lazy_static::initialize(&CERTIFICATE_CHAIN_LENGTH);
    lazy_static::initialize(&VALIDATION_DURATION_SECONDS);
    lazy_static::initialize(&GET_ENTRIES_REQUESTS);
    lazy_static::initialize(&GET_ENTRIES_BATCH_SIZE);
    lazy_static::initialize(&INCLUSION_PROOF_REQUESTS);
    lazy_static::initialize(&CONSISTENCY_PROOF_REQUESTS);
    lazy_static::initialize(&HEALTH_CHECK_STATUS);
}
