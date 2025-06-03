use crate::types::{CtError, Result};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};

/// Signed Tree Head (STH) as defined in RFC 6962
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Tree size (number of leaves)
    pub tree_size: u64,

    /// Timestamp in milliseconds since epoch
    pub timestamp: u64,

    /// Root hash of the Merkle tree
    pub root_hash: Vec<u8>,

    /// Digital signature over the tree head
    pub signature: Vec<u8>,
}

impl SignedTreeHead {
    /// Create a new STH (without signature)
    pub fn new(tree_size: u64, timestamp: u64, root_hash: Vec<u8>) -> Self {
        Self {
            tree_size,
            timestamp,
            root_hash,
            signature: Vec::new(),
        }
    }

    /// Get the data that needs to be signed for this STH
    pub fn get_signature_input(&self) -> Vec<u8> {
        let mut input = Vec::new();

        // SignatureType: tree_hash (1)
        input.push(1);

        // Timestamp (8 bytes)
        input.extend_from_slice(&self.timestamp.to_be_bytes());

        // Tree size (8 bytes)
        input.extend_from_slice(&self.tree_size.to_be_bytes());

        // Root hash (32 bytes for SHA-256)
        input.extend_from_slice(&self.root_hash);

        input
    }

    /// Convert to the format expected by CT API responses
    pub fn to_api_response(&self) -> SthResponse {
        SthResponse {
            tree_size: self.tree_size,
            timestamp: self.timestamp,
            sha256_root_hash: {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                STANDARD.encode(&self.root_hash)
            },
            tree_head_signature: {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                // Create the DigitallySigned structure
                let mut digitally_signed = Vec::new();
                // Hash algorithm: SHA256 (4)
                digitally_signed.push(4);
                // Signature algorithm: ECDSA (3)
                digitally_signed.push(3);
                // Signature length (2 bytes)
                let sig_len = self.signature.len() as u16;
                digitally_signed.extend_from_slice(&sig_len.to_be_bytes());
                // The actual signature
                digitally_signed.extend_from_slice(&self.signature);
                STANDARD.encode(&digitally_signed)
            },
        }
    }
}

/// STH response format for the CT API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SthResponse {
    pub tree_size: u64,
    pub timestamp: u64,
    pub sha256_root_hash: String,
    pub tree_head_signature: String,
}

pub struct SthBuilder {
    signing_key: SigningKey,
}

impl SthBuilder {
    pub fn from_private_key_bytes(private_key_bytes: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key_bytes)
            .map_err(|_| CtError::InvalidCertificate("Invalid private key".into()))?;
        Ok(Self { signing_key })
    }

    pub fn create_sth(&self, tree_size: u64, root_hash: Vec<u8>) -> Result<SignedTreeHead> {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let mut sth = SignedTreeHead::new(tree_size, timestamp, root_hash);

        let signature_input = sth.get_signature_input();

        let signature: Signature = self.signing_key.sign(&signature_input);
        sth.signature = signature.to_bytes().to_vec();

        Ok(sth)
    }
}

/// Checkpoint format for CT logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Log identifier
    pub log_id: String,

    /// Tree size
    pub tree_size: u64,

    /// Root hash (hex-encoded)
    pub root_hash: String,

    /// Timestamp
    pub timestamp: u64,

    pub consistency_proof: Option<Vec<String>>,
}
