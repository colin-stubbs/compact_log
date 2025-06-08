use chrono::{DateTime, Utc};
use der::{asn1::ObjectIdentifier, Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::Certificate;

pub mod sct;
pub mod tree_head;

/// Log entry type according to RFC 6962
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

#[derive(Error, Debug)]
pub enum CtError {
    #[error("Invalid certificate format: {0}")]
    InvalidCertificate(String),

    #[error("Storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CtError>;

/// Log ID (SHA-256 hash of the log's public key)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogId([u8; 32]);

impl LogId {
    pub fn new(public_key_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key_der);
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        Self(id)
    }
}

/// Certificate entry in the log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// The index of this entry in the log
    pub index: u64,

    /// Timestamp when the certificate was added
    pub timestamp: DateTime<Utc>,

    /// The entry type (X509 or Precert)
    pub entry_type: LogEntryType,

    /// The certificate data (DER-encoded)
    pub certificate: Vec<u8>,

    /// Optional certificate chain
    pub chain: Option<Vec<Vec<u8>>>,

    /// For pre-certificates: the issuer key hash (32 bytes)
    pub issuer_key_hash: Option<Vec<u8>>,

    /// For pre-certificates: the original pre-certificate (before poison extension removal)
    pub original_precert: Option<Vec<u8>>,

    /// The serialized MerkleTreeLeaf data NOT the hash
    pub leaf_data: Vec<u8>,
}

/// Deduplicated certificate entry that stores certificate hashes instead of full data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicatedLogEntry {
    /// The index of this entry in the log
    pub index: u64,

    /// Timestamp when the certificate was added
    pub timestamp: DateTime<Utc>,

    /// The entry type (X509 or Precert)
    pub entry_type: LogEntryType,

    /// SHA-256 hash of the certificate data (pointer to cert store)
    pub certificate_hash: [u8; 32],

    /// Optional certificate chain as array of certificate hashes
    pub chain_hashes: Option<Vec<[u8; 32]>>,

    /// For pre-certificates: the issuer key hash (32 bytes)
    pub issuer_key_hash: Option<[u8; 32]>,

    /// For pre-certificates: hash of the original pre-certificate
    pub original_precert_hash: Option<[u8; 32]>,

    /// The serialized MerkleTreeLeaf data NOT the hash
    pub leaf_data: Vec<u8>,
}

/// CT Poison Extension OID: 1.3.6.1.4.1.11129.2.4.3
const POISON_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.3");

impl DeduplicatedLogEntry {
    /// Create a new deduplicated log entry from a regular log entry
    pub fn from_log_entry(entry: &LogEntry) -> Self {
        // Hash the certificate
        let mut hasher = Sha256::new();
        hasher.update(&entry.certificate);
        let certificate_hash = hasher.finalize().into();

        // Hash the chain certificates if present
        let chain_hashes = entry.chain.as_ref().map(|chain| {
            chain
                .iter()
                .map(|cert| {
                    let mut hasher = Sha256::new();
                    hasher.update(cert);
                    hasher.finalize().into()
                })
                .collect()
        });

        // Hash the original precert if present
        let original_precert_hash = entry.original_precert.as_ref().map(|precert| {
            let mut hasher = Sha256::new();
            hasher.update(precert);
            hasher.finalize().into()
        });

        // Convert issuer_key_hash from Vec<u8> to [u8; 32] if present
        let issuer_key_hash = entry.issuer_key_hash.as_ref().map(|hash| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash[..32]);
            arr
        });

        Self {
            index: entry.index,
            timestamp: entry.timestamp,
            entry_type: entry.entry_type,
            certificate_hash,
            chain_hashes,
            issuer_key_hash,
            original_precert_hash,
            leaf_data: entry.leaf_data.clone(),
        }
    }

    /// Compute SHA-256 hash of certificate data
    pub fn hash_certificate(certificate: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(certificate);
        hasher.finalize().into()
    }
}

impl LogEntry {
    pub fn new_with_timestamp(
        index: u64,
        certificate: Vec<u8>,
        chain: Option<Vec<Vec<u8>>>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let entry_type = LogEntryType::X509Entry;
        let leaf_data = Self::compute_leaf_data(&certificate, entry_type, None, timestamp);

        Self {
            index,
            timestamp,
            entry_type,
            certificate,
            chain,
            issuer_key_hash: None,
            original_precert: None,
            leaf_data,
        }
    }

    pub fn new_precert_with_timestamp(
        index: u64,
        certificate: Vec<u8>,
        chain: Option<Vec<Vec<u8>>>,
        issuer_key_hash: Vec<u8>,
        original_precert: Vec<u8>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let entry_type = LogEntryType::PrecertEntry;
        let leaf_data =
            Self::compute_leaf_data(&certificate, entry_type, Some(&issuer_key_hash), timestamp);

        Self {
            index,
            timestamp,
            entry_type,
            certificate,
            chain,
            issuer_key_hash: Some(issuer_key_hash),
            original_precert: Some(original_precert),
            leaf_data,
        }
    }

    /// Serialize MerkleTreeLeaf structure for a given entry data
    fn serialize_merkle_tree_leaf(
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: DateTime<Utc>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // Version (1 byte) - RFC 6962 MerkleTreeLeaf version is always 0
        data.push(0x00);

        // LeafType (1 byte) - always timestamped_entry (0)
        data.push(0x00);

        // Timestamp (8 bytes, milliseconds since epoch)
        data.extend_from_slice(&(timestamp.timestamp_millis() as u64).to_be_bytes());

        // LogEntryType (2 bytes)
        match entry_type {
            LogEntryType::X509Entry => {
                data.extend_from_slice(&[0x00, 0x00]);

                // Certificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                data.push((cert_len >> 16) as u8);
                data.push((cert_len >> 8) as u8);
                data.push(cert_len as u8);

                // Certificate data
                data.extend_from_slice(certificate);
            }
            LogEntryType::PrecertEntry => {
                data.extend_from_slice(&[0x00, 0x01]);

                // PreCert structure: issuer_key_hash[32] + TBSCertificate
                if let Some(key_hash) = issuer_key_hash {
                    // Issuer key hash (32 bytes) - directly included, no length prefix
                    data.extend_from_slice(key_hash);
                } else {
                    // This should not happen for precerts, but handle gracefully
                    data.extend_from_slice(&[0u8; 32]);
                }

                // TBSCertificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                data.push((cert_len >> 16) as u8);
                data.push((cert_len >> 8) as u8);
                data.push(cert_len as u8);

                // TBSCertificate data
                data.extend_from_slice(certificate);
            }
        }

        // Extensions length (2 bytes) - no extensions for now
        data.extend_from_slice(&[0x00, 0x00]);

        data
    }

    /// Get the serialized leaf data for the Merkle tree
    /// This returns the serialized MerkleTreeLeaf that will be hashed
    pub fn compute_leaf_data(
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: DateTime<Utc>,
    ) -> Vec<u8> {
        // Note: This returns serialized data, not a hash. The actual leaf hash                                                       │ │
        // is computed as SHA256(0x00 || this_data) in the storage layer
        Self::serialize_merkle_tree_leaf(certificate, entry_type, issuer_key_hash, timestamp)
    }

    /// Check if a certificate is a pre-certificate by looking for the poison extension
    pub fn is_precertificate(certificate_der: &[u8]) -> Result<bool> {
        let cert = Certificate::from_der(certificate_der).map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to parse certificate: {}", e))
        })?;

        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == POISON_EXTENSION_OID {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Extract issuer key hash from the certificate chain
    /// For pre-certificates, we need the SHA-256 hash of the issuer's SubjectPublicKeyInfo
    pub fn extract_issuer_key_hash(chain: &[Vec<u8>]) -> Result<Vec<u8>> {
        if chain.len() < 2 {
            return Err(CtError::InvalidCertificate(
                "Pre-certificate chain must contain at least issuer certificate".to_string(),
            ));
        }

        let issuer_cert_der = &chain[1];
        let issuer_cert = Certificate::from_der(issuer_cert_der).map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to parse issuer certificate: {}", e))
        })?;

        let spki_der = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| CtError::InvalidCertificate(format!("Failed to encode SPKI: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&spki_der);
        Ok(hasher.finalize().to_vec())
    }

    /// Remove the poison extension from a pre-certificate to get the TBSCertificate
    pub fn remove_poison_extension(certificate_der: &[u8]) -> Result<Vec<u8>> {
        let mut cert = Certificate::from_der(certificate_der).map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to parse certificate: {}", e))
        })?;

        if let Some(ref mut extensions) = cert.tbs_certificate.extensions {
            extensions.retain(|ext| ext.extn_id != POISON_EXTENSION_OID);

            // If no extensions remain, set extensions to None
            if extensions.is_empty() {
                cert.tbs_certificate.extensions = None;
            }
        }

        // Return the TBSCertificate (without the signature)
        cert.tbs_certificate.to_der().map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to encode TBSCertificate: {}", e))
        })
    }

    /// Serialize the log entry to CT binary format
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let issuer_key_hash = match self.entry_type {
            LogEntryType::X509Entry => None,
            LogEntryType::PrecertEntry => {
                if let Some(ref key_hash) = self.issuer_key_hash {
                    Some(key_hash.as_slice())
                } else {
                    return Err(CtError::InvalidCertificate(
                        "Pre-certificate entry missing issuer key hash".to_string(),
                    ));
                }
            }
        };

        let data = Self::serialize_merkle_tree_leaf(
            &self.certificate,
            self.entry_type,
            issuer_key_hash,
            self.timestamp,
        );

        Ok(data)
    }

}

/// Request to add a certificate to the log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddChainRequest {
    /// The certificate chain (array of base64-encoded DER certificates)
    /// The first certificate is the end-entity certificate
    pub chain: Vec<String>,
}

/// Response to adding a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddChainResponse {
    /// The SCT for this certificate
    pub sct_version: u8,
    pub id: String,
    pub timestamp: u64,
    pub extensions: String,
    pub signature: String,
}

/// Request for an inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProofByHashRequest {
    pub hash: String,
    pub tree_size: u64,
}

/// Response containing an inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProofByHashResponse {
    pub leaf_index: u64,
    pub audit_path: Vec<String>,
}

/// Request for a consistency proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetConsistencyProofRequest {
    pub first: u64,
    pub second: u64,
}

/// Response containing a consistency proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetConsistencyProofResponse {
    pub consistency: Vec<String>,
}

/// Request for log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEntriesRequest {
    pub start: u64,
    pub end: u64,
}

/// Response containing log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEntriesResponse {
    pub entries: Vec<LeafEntry>,
}

/// A leaf entry in the response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafEntry {
    pub leaf_input: String,
    pub extra_data: String,
}
