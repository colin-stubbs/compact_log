use crate::types::CtError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub enabled: bool,
    pub trusted_roots_dir: PathBuf,
    pub temporal_window_start: DateTime<Utc>,
    pub temporal_window_end: DateTime<Utc>,
    pub max_chain_length: usize,
    pub allowed_signature_algorithms: HashSet<String>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_roots_dir: PathBuf::from("trusted_roots"),
            temporal_window_start: Utc::now(),
            temporal_window_end: Utc::now() + chrono::Duration::days(365),
            max_chain_length: 5,
            allowed_signature_algorithms: vec![
                "ecdsa-with-sha256".to_string(),
                "ecdsa-with-sha384".to_string(),
                "sha256-with-rsa-encryption".to_string(),
                "sha384-with-rsa-encryption".to_string(),
            ]
            .into_iter()
            .collect(),
        }
    }
}

pub struct CertificateValidator {
    config: ValidationConfig,
    trusted_roots: Vec<Certificate>,
}

impl CertificateValidator {
    pub fn new(config: ValidationConfig) -> Result<Self, CtError> {
        let trusted_roots = Self::load_trusted_roots(&config.trusted_roots_dir)?;

        Ok(Self {
            config,
            trusted_roots,
        })
    }

    fn load_trusted_roots(dir: &Path) -> Result<Vec<Certificate>, CtError> {
        let mut roots = Vec::new();

        if !dir.exists() {
            return Ok(roots);
        }

        for entry in fs::read_dir(dir).map_err(|e| {
            CtError::Internal(format!("Failed to read trusted roots directory: {}", e))
        })? {
            let entry = entry
                .map_err(|e| CtError::Internal(format!("Failed to read directory entry: {}", e)))?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                let pem_data = fs::read_to_string(&path).map_err(|e| {
                    CtError::Internal(format!("Failed to read PEM file {:?}: {}", path, e))
                })?;

                let (label, der_bytes) =
                    pem_rfc7468::decode_vec(&pem_data.as_bytes()).map_err(|e| {
                        CtError::Internal(format!("Failed to parse PEM file {:?}: {}", path, e))
                    })?;

                if label != "CERTIFICATE" {
                    return Err(CtError::Internal(format!(
                        "Invalid PEM label in {:?}: expected CERTIFICATE, got {}",
                        path, label
                    )));
                }

                let cert = Certificate::from_der(&der_bytes).map_err(|e| {
                    CtError::Internal(format!(
                        "Failed to parse certificate from {:?}: {}",
                        path, e
                    ))
                })?;

                roots.push(cert);
            }
        }

        Ok(roots)
    }

    pub fn validate_chain(&self, chain: &[Vec<u8>]) -> Result<(), CtError> {
        if !self.config.enabled {
            return Ok(());
        }

        if chain.is_empty() {
            return Err(CtError::BadRequest(
                "Certificate chain is empty".to_string(),
            ));
        }

        if chain.len() > self.config.max_chain_length {
            return Err(CtError::BadRequest(format!(
                "Certificate chain length {} exceeds maximum {}",
                chain.len(),
                self.config.max_chain_length
            )));
        }

        // Parse all certificates
        let mut certs = Vec::new();
        for (i, cert_der) in chain.iter().enumerate() {
            let cert = Certificate::from_der(cert_der).map_err(|e| {
                CtError::BadRequest(format!("Failed to parse certificate at index {}: {}", i, e))
            })?;
            certs.push(cert);
        }

        // Check temporal constraints on the leaf certificate
        self.check_temporal_constraints(&certs[0])?;

        // Validate signature algorithms
        for cert in &certs {
            self.validate_signature_algorithm(cert)?;
        }

        // Validate chain to trusted root
        self.validate_chain_to_root(&certs)?;

        Ok(())
    }

    fn check_temporal_constraints(&self, cert: &Certificate) -> Result<(), CtError> {
        let not_before = cert.tbs_certificate.validity.not_before.to_system_time();
        let not_after = cert.tbs_certificate.validity.not_after.to_system_time();

        let not_before_dt: DateTime<Utc> = not_before.into();
        let not_after_dt: DateTime<Utc> = not_after.into();

        // Check if certificate validity period overlaps with our acceptance window
        if not_after_dt < self.config.temporal_window_start {
            return Err(CtError::BadRequest(format!(
                "Certificate expired before log acceptance window starts: {} < {}",
                not_after_dt.format("%Y-%m-%d %H:%M:%S UTC"),
                self.config
                    .temporal_window_start
                    .format("%Y-%m-%d %H:%M:%S UTC")
            )));
        }

        if not_before_dt > self.config.temporal_window_end {
            return Err(CtError::BadRequest(format!(
                "Certificate not valid until after log acceptance window ends: {} > {}",
                not_before_dt.format("%Y-%m-%d %H:%M:%S UTC"),
                self.config
                    .temporal_window_end
                    .format("%Y-%m-%d %H:%M:%S UTC")
            )));
        }

        Ok(())
    }

    fn validate_signature_algorithm(&self, cert: &Certificate) -> Result<(), CtError> {
        let sig_alg = cert.signature_algorithm.oid.to_string();

        // Map OIDs to algorithm names
        let alg_name = match sig_alg.as_str() {
            "1.2.840.10045.4.3.2" => "ecdsa-with-sha256",
            "1.2.840.10045.4.3.3" => "ecdsa-with-sha384",
            "1.2.840.113549.1.1.11" => "sha256-with-rsa-encryption",
            "1.2.840.113549.1.1.12" => "sha384-with-rsa-encryption",
            "1.2.840.113549.1.1.5" => "sha1-with-rsa-encryption",

            _ => &sig_alg,
        };

        if !self.config.allowed_signature_algorithms.contains(alg_name) {
            return Err(CtError::BadRequest(format!(
                "Signature algorithm '{}' not allowed",
                alg_name
            )));
        }

        Ok(())
    }

    fn validate_chain_to_root(&self, chain: &[Certificate]) -> Result<(), CtError> {
        if chain.is_empty() {
            return Err(CtError::Internal("Empty certificate chain".to_string()));
        }

        // Check if the last certificate in the chain is a trusted root
        let last_cert = &chain[chain.len() - 1];

        let is_trusted_root = self.trusted_roots.iter().any(|root| {
            // Compare by subject and public key
            root.tbs_certificate.subject == last_cert.tbs_certificate.subject
                && root.tbs_certificate.subject_public_key_info
                    == last_cert.tbs_certificate.subject_public_key_info
        });

        if !is_trusted_root {
            // Check if any intermediate cert is issued by a trusted root
            for cert in chain {
                for root in &self.trusted_roots {
                    if cert.tbs_certificate.issuer == root.tbs_certificate.subject {
                        // Found a certificate issued by a trusted root
                        // In a full implementation, we would verify the signature here
                        return Ok(());
                    }
                }
            }

            return Err(CtError::BadRequest(
                "Certificate chain does not terminate in a trusted root".to_string(),
            ));
        }

        Ok(())
    }

    pub fn get_accepted_root_certificates(&self) -> Result<Vec<Vec<u8>>, CtError> {
        self.trusted_roots
            .iter()
            .map(|cert| {
                cert.to_der().map_err(|e| {
                    CtError::Internal(format!("Failed to encode certificate to DER: {}", e))
                })
            })
            .collect()
    }

    pub fn get_temporal_window(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        (
            self.config.temporal_window_start,
            self.config.temporal_window_end,
        )
    }
}
