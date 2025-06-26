use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Version {
    V1 = 0,
}

#[derive(Debug, Clone)]
pub struct EntriesPage {
    pub format_version: Version,
    pub entry_count: u64,
    pub first_entry_index: u64,
    pub entries: Vec<PageEntry>,
}

#[derive(Debug, Clone)]
pub struct PageEntry {
    pub timestamped_entry: Vec<u8>,   // RFC 6962 TimestampedEntry binary
    pub issuer_hashes: Vec<[u8; 32]>, // SHA-256 hashes of issuer certificates
}

impl EntriesPage {
    pub fn new(first_entry_index: u64) -> Self {
        Self {
            format_version: Version::V1,
            entry_count: 0,
            first_entry_index,
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, timestamped_entry: Vec<u8>, issuer_hashes: Vec<[u8; 32]>) {
        self.entries.push(PageEntry {
            timestamped_entry,
            issuer_hashes,
        });
        self.entry_count += 1;
    }

    pub fn to_binary(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Version (1 byte)
        result.push(self.format_version as u8);

        // Entry count (8 bytes, big-endian)
        result.extend_from_slice(&self.entry_count.to_be_bytes());

        // First entry index (8 bytes, big-endian)
        result.extend_from_slice(&self.first_entry_index.to_be_bytes());

        // Entries
        for entry in &self.entries {
            // TimestampedEntry length (4 bytes, big-endian)
            result.extend_from_slice(&(entry.timestamped_entry.len() as u32).to_be_bytes());
            // TimestampedEntry data
            result.extend_from_slice(&entry.timestamped_entry);

            // Chain length (2 bytes, big-endian)
            result.extend_from_slice(&(entry.issuer_hashes.len() as u16).to_be_bytes());

            // Issuer hashes
            for hash in &entry.issuer_hashes {
                result.extend_from_slice(hash);
            }
        }

        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub page_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_endpoint: Option<String>,
}

pub fn base64url_to_hash(s: &str) -> Result<[u8; 32], String> {
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("Invalid base64url: {}", e))?;

    if bytes.len() != 32 {
        return Err(format!(
            "Invalid hash length: expected 32, got {}",
            bytes.len()
        ));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
