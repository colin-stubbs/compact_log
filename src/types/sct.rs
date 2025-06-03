use crate::types::{CtError, LogEntryType, LogId, Result};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};

/// Version of the SCT structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SctVersion {
    V1 = 0,
}

/// Signed Certificate Timestamp (SCT) as defined in RFC 6962
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificateTimestamp {
    /// SCT version
    pub version: SctVersion,

    /// Log ID (32-byte SHA-256 hash of the log's public key)
    pub log_id: LogId,

    /// Timestamp in milliseconds since epoch
    pub timestamp: u64,

    /// Extensions (currently unused, but included for future compatibility)
    pub extensions: Vec<u8>,

    /// Digital signature over the SCT data
    pub signature: Vec<u8>,
}

impl SignedCertificateTimestamp {
    /// Create a new SCT (without signature - must be signed separately)
    pub fn new(log_id: LogId, timestamp: u64) -> Self {
        Self {
            version: SctVersion::V1,
            log_id,
            timestamp,
            extensions: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// Get the data that needs to be signed for this SCT
    pub fn get_signature_input(
        &self,
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut input = Vec::new();

        // SignatureType: certificate_timestamp (0)
        input.push(0);

        // Timestamp (8 bytes)
        input.extend_from_slice(&self.timestamp.to_be_bytes());

        // LogEntryType
        match entry_type {
            LogEntryType::X509Entry => {
                input.extend_from_slice(&[0, 0]);

                // Certificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                input.push((cert_len >> 16) as u8);
                input.push((cert_len >> 8) as u8);
                input.push(cert_len as u8);

                // Certificate data
                input.extend_from_slice(certificate);
            }
            LogEntryType::PrecertEntry => {
                input.extend_from_slice(&[0, 1]);

                // Issuer key hash (32 bytes) - required for pre-certificates
                if let Some(key_hash) = issuer_key_hash {
                    input.extend_from_slice(key_hash);
                } else {
                    // This should not happen for precerts
                    input.extend_from_slice(&[0u8; 32]);
                }

                // TBSCertificate length (3 bytes)
                let cert_len = certificate.len() as u32;
                input.push((cert_len >> 16) as u8);
                input.push((cert_len >> 8) as u8);
                input.push(cert_len as u8);

                // TBSCertificate data
                input.extend_from_slice(certificate);
            }
        }

        // Extensions length (2 bytes)
        let ext_len = self.extensions.len() as u16;
        input.extend_from_slice(&ext_len.to_be_bytes());

        // Extensions data
        input.extend_from_slice(&self.extensions);

        input
    }
}

impl LogId {
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Builder for creating SCTs with proper signatures
pub struct SctBuilder {
    log_id: LogId,
    signing_key: SigningKey,
}

impl SctBuilder {
    pub fn from_private_key_bytes(log_id: LogId, private_key_bytes: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key_bytes)
            .map_err(|_| CtError::InvalidCertificate("Invalid private key".into()))?;
        Ok(Self {
            log_id,
            signing_key,
        })
    }

    /// Create and sign an SCT for a certificate with a specific timestamp
    pub fn create_sct_with_timestamp(
        &self,
        certificate: &[u8],
        entry_type: LogEntryType,
        issuer_key_hash: Option<&[u8]>,
        timestamp: u64,
    ) -> Result<SignedCertificateTimestamp> {
        let mut sct = SignedCertificateTimestamp::new(self.log_id.clone(), timestamp);

        let signature_input = sct.get_signature_input(certificate, entry_type, issuer_key_hash);

        let signature: Signature = self.signing_key.sign(&signature_input);

        let mut tls_signature = Vec::new();

        // SignatureAndHashAlgorithm: hash(1 byte) + signature(1 byte)
        // SHA-256 = 4, ECDSA = 3 (from RFC 5246)
        tls_signature.push(4); // SHA-256
        tls_signature.push(3); // ECDSA

        // Signature length (2 bytes) + signature data
        let sig_bytes = signature.to_bytes();
        let sig_len = sig_bytes.len() as u16;
        tls_signature.extend_from_slice(&sig_len.to_be_bytes());
        tls_signature.extend_from_slice(&sig_bytes);

        sct.signature = tls_signature;

        Ok(sct)
    }
}
