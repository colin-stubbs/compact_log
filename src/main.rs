use config::Config;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::LineEnding;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use slatedb::config::{
    CompactorOptions, CompressionCodec, GarbageCollectorDirectoryOptions, GarbageCollectorOptions,
    ObjectStoreCacheOptions, SstIteratorOptions,
};
use slatedb::db_cache::moka::{MokaCache, MokaCacheOptions};
use slatedb::{
    object_store::{
        aws::AmazonS3Builder, azure::MicrosoftAzureBuilder, local::LocalFileSystem, path::Path,
        ObjectStore,
    },
    Db, Settings,
};
use tokio::runtime::{Handle, Runtime};

use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{default, fs};
use tokio::net::TcpListener;
use tracing::info;

mod api;
mod merkle_storage;
mod merkle_tree;
mod storage;
mod types;
mod validation;

#[cfg(test)]
mod test_utils;

use api::{create_router, ApiState};
use storage::{BatchConfig, CtStorage};
use types::LogId;
use validation::{CertificateValidator, ValidationConfig};

#[derive(Debug, Deserialize, Serialize)]
struct StorageConfig {
    provider: String,
    azure: Option<AzureConfig>,
    aws: Option<AwsConfig>,
    local: Option<LocalConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AzureConfig {
    account: String,
    access_key: String,
    container_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AwsConfig {
    region: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct LocalConfig {
    path: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AppConfig {
    server: ServerConfig,
    storage: StorageConfig,
    keys: KeysConfig,
    validation: Option<ValidationConfig>,
    cache: Option<CacheConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ServerConfig {
    bind_addr: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeysConfig {
    private_key_path: String,
    public_key_path: String,
}

const DEFAULT_MEMORY_BLOCK_CACHE_CAPACITY_MB: u64 = 64; // 64 MB default

#[derive(Debug, Deserialize, Serialize)]
struct CacheConfig {
    root_folder: Option<String>,
    max_cache_size_gb: Option<u64>,
    #[serde(default = "default_memory_block_cache_capacity_mb")]
    memory_block_cache_capacity_mb: u64,
}

fn default_memory_block_cache_capacity_mb() -> u64 {
    DEFAULT_MEMORY_BLOCK_CACHE_CAPACITY_MB
}

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    info!("Starting Certificate Transparency Log");

    let config = load_config().await?;

    let bind_addr = &config.server.bind_addr;

    let background_runtime = Runtime::new().unwrap();

    let (storage, _db_path, _object_store) = initialize_storage(
        &config.storage,
        &config.cache,
        background_runtime.handle().clone(),
    )
    .await?;

    // Load keys from config
    let private_key = load_private_key(&config.keys.private_key_path)?;
    let public_key_der = derive_public_key_der_from_p256(&private_key);
    let log_id = LogId::new(&public_key_der);

    info!("Log ID: {}", log_id.to_hex());

    let batch_config = BatchConfig::default();

    info!("Creating merkle tree...");
    info!("DB initialized, attempting to create StorageBackedMerkleTree");

    let merkle_tree = merkle_storage::StorageBackedMerkleTree::new(storage.clone()).await?;
    info!("StorageBackedMerkleTree created successfully");

    info!("Merkle tree created");

    info!("Creating CT storage...");

    let ct_storage = CtStorage::new(storage, batch_config, merkle_tree.clone()).await?;

    info!("CT storage created");

    // Initialize certificate validator if validation is configured
    let validator = match config.validation {
        Some(validation_config) => {
            info!("Certificate validation enabled");
            Some(Arc::new(CertificateValidator::new(validation_config)?))
        }
        None => {
            info!("Certificate validation disabled");
            None
        }
    };

    let private_key_bytes = private_key.to_bytes().to_vec();
    let api_state = ApiState::new(
        Arc::new(ct_storage),
        merkle_tree,
        log_id,
        private_key_bytes,
        validator,
    )?;

    let app = create_router(api_state);

    info!("Listening on {}", bind_addr);

    let listener = TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn load_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    if !StdPath::new("Config.toml").exists() {
        info!("Config.toml not found, creating default configuration with new keys");
        return initialize_config().await;
    }

    let config = Config::builder()
        .add_source(config::File::with_name("Config"))
        .build()?;

    let app_config: AppConfig = config.try_deserialize()?;

    ensure_keys_exist(&app_config.keys).await?;

    Ok(app_config)
}

async fn initialize_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    let config = AppConfig {
        server: ServerConfig {
            bind_addr: "0.0.0.0:8080".to_string(),
        },
        storage: StorageConfig {
            provider: "local".to_string(),
            azure: None,
            aws: None,
            local: Some(LocalConfig {
                path: "/tmp/ct-log-storage".to_string(),
            }),
        },
        keys: KeysConfig {
            private_key_path: "keys/private_key.pem".to_string(),
            public_key_path: "keys/public_key.pem".to_string(),
        },
        validation: None,
        cache: None,
    };

    fs::create_dir_all("keys")?;
    generate_and_save_keys(&config.keys).await?;

    let config_content = toml::to_string(&config)?;
    fs::write("Config.toml", config_content)?;

    info!("Created Config.toml with new keys in keys/ directory");

    Ok(config)
}

async fn ensure_keys_exist(keys_config: &KeysConfig) -> Result<(), Box<dyn std::error::Error>> {
    if !StdPath::new(&keys_config.private_key_path).exists()
        || !StdPath::new(&keys_config.public_key_path).exists()
    {
        info!("Key files not found, generating new keys");
        if let Some(parent) = StdPath::new(&keys_config.private_key_path).parent() {
            fs::create_dir_all(parent)?;
        }
        generate_and_save_keys(keys_config).await?;
    }
    Ok(())
}

async fn generate_and_save_keys(
    keys_config: &KeysConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let private_key = SecretKey::random(&mut rand::rngs::OsRng);
    let public_key = private_key.public_key();

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF)?;

    fs::write(&keys_config.private_key_path, private_key_pem.as_bytes())?;
    fs::write(&keys_config.public_key_path, public_key_pem.as_bytes())?;

    info!("Generated new key pair:");
    info!("  Private key: {}", keys_config.private_key_path);
    info!("  Public key: {}", keys_config.public_key_path);

    Ok(())
}

fn load_private_key(path: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let pem_content = fs::read_to_string(path)?;
    let private_key = SecretKey::from_pkcs8_pem(&pem_content)?;
    Ok(private_key)
}

async fn initialize_storage(
    storage_config: &StorageConfig,
    cache_config: &Option<CacheConfig>,
    background_runtime: Handle,
) -> Result<(Arc<Db>, Path, Arc<dyn ObjectStore>), Box<dyn std::error::Error>> {
    // Memory block cache can be configured independently of local file cache
    let memory_block_cache_mb = cache_config
        .as_ref()
        .map(|c| c.memory_block_cache_capacity_mb)
        .unwrap_or(DEFAULT_MEMORY_BLOCK_CACHE_CAPACITY_MB);

    let mut cache_options = MokaCacheOptions::default();
    cache_options.max_capacity = memory_block_cache_mb * 1024 * 1024; // Convert MB to bytes

    let block_cache = Arc::new(MokaCache::new_with_opts(cache_options));

    let garbage_collector_directory_options = GarbageCollectorDirectoryOptions {
        min_age: Duration::from_secs(60 * 60),
        ..default::Default::default()
    };

    let mut db_options = Settings::default();
    db_options.compression_codec = Some(CompressionCodec::Lz4);
    db_options.garbage_collector_options = Some(GarbageCollectorOptions {
        wal_options: Some(garbage_collector_directory_options),
        manifest_options: Some(garbage_collector_directory_options),
        compacted_options: Some(garbage_collector_directory_options),
        ..default::Default::default()
    });

    let compactor_options: CompactorOptions = CompactorOptions {
        max_sst_size: 64 * 1024 * 1024, // 64 MB
        poll_interval: Duration::from_millis(100),
        max_concurrent_compactions: 16,
        sst_iterator_options: SstIteratorOptions {
            max_fetch_tasks: 16,
            blocks_to_fetch: 2048,
            cache_blocks: true,
            eager_spawn: true,
        },
        ..default::Default::default()
    };

    db_options.compactor_options = Some(compactor_options);

    db_options.object_store_cache_options = match cache_config {
        Some(cache) => {
            // Only set object store cache if root_folder is provided
            match (&cache.root_folder, &cache.max_cache_size_gb) {
                (Some(root_folder), Some(max_size_gb)) => ObjectStoreCacheOptions {
                    root_folder: Some(PathBuf::from(root_folder)),
                    max_cache_size_bytes: Some((max_size_gb * 1024 * 1024 * 1024) as usize),
                    ..default::Default::default()
                },
                (Some(root_folder), None) => ObjectStoreCacheOptions {
                    root_folder: Some(PathBuf::from(root_folder)),
                    ..default::Default::default()
                },
                _ => ObjectStoreCacheOptions::default(),
            }
        }
        None => ObjectStoreCacheOptions::default(),
    };

    let path = Path::from("ct_log");
    let blob_store: Arc<dyn ObjectStore> = match storage_config.provider.as_str() {
        "azure" => {
            let azure_config = storage_config
                .azure
                .as_ref()
                .ok_or("Azure configuration is required when provider is 'azure'")?;
            Arc::new(
                MicrosoftAzureBuilder::new()
                    .with_account(&azure_config.account)
                    .with_access_key(&azure_config.access_key)
                    .with_container_name(&azure_config.container_name)
                    .build()?,
            )
        }
        "aws" => {
            let aws_config = storage_config
                .aws
                .as_ref()
                .ok_or("AWS configuration is required when provider is 'aws'")?;
            Arc::new(
                AmazonS3Builder::new()
                    .with_region(&aws_config.region)
                    .with_bucket_name(&aws_config.bucket)
                    .with_access_key_id(&aws_config.access_key_id)
                    .with_secret_access_key(&aws_config.secret_access_key)
                    .build()?,
            )
        }
        "local" => {
            let local_config = storage_config
                .local
                .as_ref()
                .ok_or("Local configuration is required when provider is 'local'")?;
            Arc::new(LocalFileSystem::new_with_prefix(&local_config.path)?)
        }
        _ => {
            return Err(format!("Unsupported storage provider: {}", storage_config.provider).into())
        }
    };

    let db = Db::builder(path.clone(), blob_store.clone())
        .with_settings(db_options)
        .with_block_cache(block_cache)
        .with_sst_block_size(65_536)
        .with_compaction_runtime(background_runtime.clone())
        .with_gc_runtime(background_runtime.clone())
        .build()
        .await
        .expect("failed to open db");

    Ok((Arc::new(db), path, blob_store))
}

fn derive_public_key_der_from_p256(private_key: &SecretKey) -> Vec<u8> {
    let public_key = private_key.public_key();
    public_key.to_encoded_point(false).as_bytes().to_vec()
}
