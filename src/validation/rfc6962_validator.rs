use crate::oids::*;
use crate::types::{CtError, Result};
use chrono::{DateTime, Utc};
use der::{Decode, Encode};
use moka::future::Cache;
use openssl::x509::X509;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use x509_cert::{
    ext::pkix::{BasicConstraints, ExtendedKeyUsage},
    Certificate,
};

const CCADB_PRODUCTION_URL: &str =
    "https://ccadb.my.salesforce-sites.com/ccadb/RootCACertificatesIncludedByRSReportCSV";
const CCADB_TEST_URL: &str =
    "https://ccadb.my.salesforce-sites.com/ccadb/RootCACertificatesInclusionReportCSV";

/// CCADB environment to use for fetching root certificates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcadbEnvironment {
    Production,
    Test,
}

impl CcadbEnvironment {
    pub fn url(&self) -> &'static str {
        match self {
            CcadbEnvironment::Production => CCADB_PRODUCTION_URL,
            CcadbEnvironment::Test => CCADB_TEST_URL,
        }
    }
}

/// Temporal window for log operation
#[derive(Debug, Clone, Copy)]
pub struct TemporalWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Configuration for RFC 6962 compliant certificate validation
#[derive(Debug, Clone)]
pub struct Rfc6962ValidationConfig {
    /// Path to directory containing trusted root certificates
    pub trusted_roots_dir: PathBuf,
    /// Maximum allowed certificate chain length
    pub max_chain_length: usize,
    /// Allowed signature algorithms (OIDs)
    pub allowed_signature_algorithms: HashSet<String>,
    /// Optional temporal window for log operation
    pub temporal_window: Option<TemporalWindow>,
    /// CCADB environment for fetching root certificates
    pub ccadb: CcadbEnvironment,
}

impl Default for Rfc6962ValidationConfig {
    fn default() -> Self {
        Self {
            trusted_roots_dir: PathBuf::from("trusted_roots"),
            max_chain_length: 10,
            allowed_signature_algorithms: vec![
                ECDSA_WITH_SHA256_OID.to_string(),
                ECDSA_WITH_SHA384_OID.to_string(),
                ECDSA_WITH_SHA512_OID.to_string(),
                SHA256_WITH_RSA_ENCRYPTION_OID.to_string(),
                SHA384_WITH_RSA_ENCRYPTION_OID.to_string(),
                SHA512_WITH_RSA_ENCRYPTION_OID.to_string(),
                SHA1_WITH_RSA_ENCRYPTION_OID.to_string(),
            ]
            .into_iter()
            .collect(),
            temporal_window: None,
            ccadb: CcadbEnvironment::Production,
        }
    }
}

/// RFC 6962 compliant certificate validator
pub struct Rfc6962Validator {
    config: Rfc6962ValidationConfig,
    pub(crate) trusted_roots: Vec<Certificate>,
    /// Hashes of trusted root certificates for fast lookup
    trusted_root_hashes: HashSet<[u8; 32]>,
    /// Cache for DER to X509 conversions
    x509_cache: Cache<[u8; 32], Arc<openssl::x509::X509>>,
}

/// Context for chain validation that captures the chain type and issuer information
#[derive(Debug)]
struct ChainValidationContext {
    /// Whether the first certificate is a precertificate
    is_precert: bool,
    /// Whether the immediate issuer is a precertificate signing certificate
    has_signing_cert: bool,
    /// Index of the real issuer in the chain
    real_issuer_index: usize,
    /// Parsed certificates
    parsed_chain: Vec<Certificate>,
}

impl Rfc6962Validator {
    /// Create a new validator with pre-loaded trusted roots
    pub fn with_trusted_roots(
        config: Rfc6962ValidationConfig,
        trusted_roots: Vec<Certificate>,
    ) -> Result<Self> {
        if trusted_roots.is_empty() {
            tracing::warn!("No trusted root certificates provided");
        }

        let trusted_root_hashes = trusted_roots
            .iter()
            .map(Self::certificate_hash)
            .collect::<Result<HashSet<_>>>()?;

        let x509_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(std::time::Duration::from_secs(3600))
            .build();

        Ok(Self {
            config,
            trusted_roots,
            trusted_root_hashes,
            x509_cache,
        })
    }

    /// Get the validation configuration
    pub fn get_config(&self) -> &Rfc6962ValidationConfig {
        &self.config
    }

    /// Analyze a certificate chain and return validation context
    fn analyze_chain(&self, chain: &[Vec<u8>]) -> Result<ChainValidationContext> {
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

        let mut parsed_chain = Vec::new();
        for (i, cert_der) in chain.iter().enumerate() {
            let cert = Certificate::from_der(cert_der).map_err(|e| {
                CtError::BadRequest(format!("Failed to parse certificate at index {}: {}", i, e))
            })?;
            parsed_chain.push(cert);
        }

        let is_precert = self.is_precertificate(&parsed_chain[0])?;

        let mut has_signing_cert = false;
        let mut real_issuer_index = 1;

        if is_precert && parsed_chain.len() >= 2 {
            has_signing_cert = self.is_precert_signing_certificate(&parsed_chain[1])?;

            if has_signing_cert {
                if parsed_chain.len() < 3 {
                    return Err(CtError::BadRequest(
                        "Precertificate signed by signing certificate requires real issuer in chain"
                            .to_string(),
                    ));
                }
                real_issuer_index = 2;
            }
        }

        Ok(ChainValidationContext {
            is_precert,
            has_signing_cert,
            real_issuer_index,
            parsed_chain,
        })
    }

    /// Validate a certificate chain according to RFC 6962
    pub async fn validate_chain(&self, chain: &[Vec<u8>]) -> Result<()> {
        let context = self.analyze_chain(chain)?;
        self.validate_chain_with_context(&context).await
    }

    /// Validate a chain using the analyzed context
    async fn validate_chain_with_context(&self, context: &ChainValidationContext) -> Result<()> {
        for (i, cert) in context.parsed_chain.iter().enumerate() {
            self.validate_certificate_basic(cert, i)?;
        }

        // Additional validation for precertificate chains
        if context.is_precert && context.has_signing_cert {
            // Verify the signing certificate is directly certified by the CA
            let signing_cert = &context.parsed_chain[1];
            let real_issuer = &context.parsed_chain[2];
            self.verify_precert_signing_cert(signing_cert, real_issuer)?;
        }

        self.verify_chain_to_root(&context.parsed_chain).await?;
        self.verify_chain_signatures(&context.parsed_chain).await?;

        Ok(())
    }

    /// Check if a certificate is a CA certificate (has Basic Constraints with CA:TRUE)
    fn is_ca_certificate(&self, cert: &Certificate) -> bool {
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == BASIC_CONSTRAINTS_OID {
                    if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                        return bc.ca;
                    }
                }
            }
        }
        false
    }

    /// Check if a certificate is a precertificate
    fn is_precertificate(&self, cert: &Certificate) -> Result<bool> {
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == CT_POISON_EXTENSION_OID {
                    if !ext.critical {
                        return Err(CtError::BadRequest(
                            "Precertificate poison extension must be critical".to_string(),
                        ));
                    }

                    if ext.extn_value.as_bytes() != ASN1_NULL {
                        return Err(CtError::BadRequest(
                            "Precertificate poison extension must contain ASN.1 NULL".to_string(),
                        ));
                    }

                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Check if a certificate is a Precertificate Signing Certificate
    fn is_precert_signing_certificate(&self, cert: &Certificate) -> Result<bool> {
        let mut has_ca_true = false;
        let mut has_ct_eku = false;

        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == BASIC_CONSTRAINTS_OID {
                    match BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                        Ok(bc) => has_ca_true = bc.ca,
                        Err(_) => continue,
                    }
                }

                if ext.extn_id == EXTENDED_KEY_USAGE_OID {
                    match ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                        Ok(eku) => {
                            for oid in eku.0.iter() {
                                if *oid == CT_EKU_OID {
                                    has_ct_eku = true;
                                    break;
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        }

        Ok(has_ca_true && has_ct_eku)
    }

    /// Verify a Precertificate Signing Certificate
    fn verify_precert_signing_cert(
        &self,
        signing_cert: &Certificate,
        real_issuer: &Certificate,
    ) -> Result<()> {
        // Verify the signing cert is directly issued by the real issuer
        if signing_cert.tbs_certificate.issuer != real_issuer.tbs_certificate.subject {
            return Err(CtError::BadRequest(
                "Precertificate Signing Certificate must be directly issued by the CA".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate basic certificate properties
    fn validate_certificate_basic(&self, cert: &Certificate, index: usize) -> Result<()> {
        let sig_alg_oid = cert.signature_algorithm.oid.to_string();
        if !self
            .config
            .allowed_signature_algorithms
            .contains(&sig_alg_oid)
        {
            return Err(CtError::BadRequest(format!(
                "Certificate at index {} uses disallowed signature algorithm: {}",
                index, sig_alg_oid
            )));
        }

        if index == 0 {
            // Only check end-entity certificate against temporal window
            if let Some(window) = self.config.temporal_window {
                let not_after: DateTime<Utc> = cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_system_time()
                    .into();

                // Check if certificate expires within the log's temporal window
                if not_after < window.start {
                    return Err(CtError::BadRequest(format!(
                        "Certificate expires before log temporal window starts: {} < {}",
                        not_after.format("%Y-%m-%d %H:%M:%S UTC"),
                        window.start.format("%Y-%m-%d %H:%M:%S UTC")
                    )));
                }

                if not_after >= window.end {
                    return Err(CtError::BadRequest(format!(
                        "Certificate expires outside log temporal window: {} >= {}",
                        not_after.format("%Y-%m-%d %H:%M:%S UTC"),
                        window.end.format("%Y-%m-%d %H:%M:%S UTC")
                    )));
                }
            }
        }

        Ok(())
    }

    /// Convert a certificate to X509
    async fn cert_to_x509(&self, cert: &Certificate) -> Result<Arc<openssl::x509::X509>> {
        let cert_der = cert
            .to_der()
            .map_err(|e| CtError::Internal(format!("Failed to encode certificate: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&cert_der);
        let der_hash: [u8; 32] = hasher.finalize().into();

        if let Some(cached) = self.x509_cache.get(&der_hash).await {
            return Ok(cached);
        }

        let x509 = X509::from_der(&cert_der)
            .map_err(|e| CtError::Internal(format!("Failed to parse certificate: {}", e)))?;
        let x509_arc = Arc::new(x509);

        // Only cache CA certificates (intermediates and roots)
        let is_ca = self.is_ca_certificate(cert);
        if is_ca {
            self.x509_cache.insert(der_hash, x509_arc.clone()).await;
        }

        Ok(x509_arc)
    }

    /// Verify the chain terminates in a trusted root
    async fn verify_chain_to_root(&self, chain: &[Certificate]) -> Result<()> {
        if self.trusted_roots.is_empty() {
            return Err(CtError::BadRequest(
                "No trusted roots configured".to_string(),
            ));
        }

        tracing::debug!(
            "Verifying chain with {} certificates against {} trusted roots",
            chain.len(),
            self.trusted_roots.len()
        );

        let last_cert = &chain[chain.len() - 1];

        // Check if the last certificate is a trusted root
        let last_cert_hash = Self::certificate_hash(last_cert)?;
        let last_cert_fingerprint = hex::encode(last_cert_hash);

        tracing::debug!(
            "Last certificate fingerprint: {}, subject: {}",
            &last_cert_fingerprint[..16],
            last_cert.tbs_certificate.subject
        );

        if self.trusted_root_hashes.contains(&last_cert_hash) {
            return Ok(());
        }

        // Log issuer of last cert for debugging
        tracing::debug!(
            "Last certificate issuer: {}",
            last_cert.tbs_certificate.issuer
        );

        let mut chain_x509s = Vec::with_capacity(chain.len());
        for cert in chain {
            chain_x509s.push(self.cert_to_x509(cert).await?);
        }

        // Check if any certificate in the chain is issued by a trusted root
        for (idx, cert) in chain.iter().enumerate() {
            let cert_subject = &cert.tbs_certificate.subject;
            let cert_issuer = &cert.tbs_certificate.issuer;

            tracing::debug!(
                "Checking cert[{}] - subject: {}, issuer: {}",
                idx,
                cert_subject,
                cert_issuer
            );

            let cert_x509 = &chain_x509s[idx];
            let mut matched_issuers = 0;

            for root in &self.trusted_roots {
                if cert.tbs_certificate.issuer == root.tbs_certificate.subject {
                    matched_issuers += 1;
                    tracing::debug!(
                        "Found potential issuer match - root subject: {}",
                        root.tbs_certificate.subject
                    );

                    let root_x509 = self.cert_to_x509(root).await?;

                    let root_pubkey = root_x509.public_key().map_err(|e| {
                        CtError::Internal(format!("Failed to extract root public key: {}", e))
                    })?;

                    match cert_x509.verify(&root_pubkey) {
                        Ok(true) => {
                            let root_hash = Self::certificate_hash(root)?;
                            let root_fingerprint = hex::encode(root_hash);
                            tracing::debug!(
                                "Certificate at index {} verified by root {} ({})",
                                idx,
                                &root_fingerprint[..16],
                                root.tbs_certificate.subject
                            );
                            return Ok(());
                        }
                        Ok(false) => {
                            tracing::debug!("Signature verification returned false");
                            continue;
                        }
                        Err(e) => {
                            tracing::debug!("Signature verification failed: {}", e);
                            continue;
                        }
                    }
                }
            }

            if matched_issuers == 0 {
                tracing::debug!(
                    "No trusted roots matched the issuer '{}' for cert[{}]",
                    cert_issuer,
                    idx
                );
            }
        }

        Err(CtError::BadRequest(
            "Certificate chain does not terminate in a trusted root".to_string(),
        ))
    }

    /// Compute SHA256 hash of a certificate's DER encoding
    fn certificate_hash(cert: &Certificate) -> Result<[u8; 32]> {
        let cert_der = cert
            .to_der()
            .map_err(|e| CtError::Internal(format!("Failed to encode certificate: {}", e)))?;
        let mut hasher = Sha256::new();
        hasher.update(&cert_der);
        Ok(hasher.finalize().into())
    }

    /// Verify signatures in the certificate chain
    async fn verify_chain_signatures(&self, chain: &[Certificate]) -> Result<()> {
        if chain.is_empty() {
            return Ok(());
        }

        let mut x509_chain = Vec::with_capacity(chain.len());
        for cert in chain {
            x509_chain.push(self.cert_to_x509(cert).await?);
        }

        // We just verify signatures directly without full chain validation
        // This allows us to handle precertificates with poison extensions

        // Verify each certificate is signed by the next one
        for i in 0..x509_chain.len() - 1 {
            let cert = &x509_chain[i];
            let issuer = &x509_chain[i + 1];

            let issuer_pubkey = issuer.public_key().map_err(|e| {
                CtError::Internal(format!(
                    "Failed to extract issuer public key at index {}: {}",
                    i + 1,
                    e
                ))
            })?;

            let verified = cert.verify(&issuer_pubkey).map_err(|e| {
                CtError::Internal(format!("Failed to verify signature at index {}: {}", i, e))
            })?;

            if !verified {
                return Err(CtError::BadRequest(format!(
                    "Certificate at index {} has invalid signature",
                    i
                )));
            }
        }

        // Verify self-signed certificates (roots)
        let last_cert = &x509_chain[x509_chain.len() - 1];
        let original_last = &chain[chain.len() - 1];

        if original_last.tbs_certificate.subject == original_last.tbs_certificate.issuer {
            let pubkey = last_cert.public_key().map_err(|e| {
                CtError::Internal(format!(
                    "Failed to extract public key from self-signed cert: {}",
                    e
                ))
            })?;

            let verified = last_cert.verify(&pubkey).map_err(|e| {
                CtError::Internal(format!("Failed to verify self-signed certificate: {}", e))
            })?;

            if !verified {
                return Err(CtError::BadRequest(
                    "Self-signed certificate has invalid signature".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Get the list of accepted root certificates
    pub fn get_accepted_roots(&self) -> Result<Vec<Vec<u8>>> {
        self.trusted_roots
            .iter()
            .map(|cert| {
                cert.to_der()
                    .map_err(|e| CtError::Internal(format!("Failed to encode certificate: {}", e)))
            })
            .collect()
    }

    pub fn extract_issuer_key_hash(&self, chain: &[Vec<u8>]) -> Result<[u8; 32]> {
        // Use the unified chain analysis to get validation context
        let context = self.analyze_chain(chain)?;

        if !context.is_precert {
            return Err(CtError::BadRequest(
                "Can only extract issuer key hash for precertificate chains".to_string(),
            ));
        }

        let real_issuer = &context.parsed_chain[context.real_issuer_index];

        let spki_der = real_issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| CtError::Internal(format!("Failed to encode SPKI: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&spki_der);
        Ok(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::tbs_extractor::TbsExtractor;
    use base64::Engine;
    use der::{asn1::OctetString, Decode, Encode};
    use std::fs;
    use tempfile::TempDir;
    use x509_cert::{
        ext::{Extension, Extensions},
        Certificate, TbsCertificate,
    };

    fn create_test_certificate_with_key(
        subject: &str,
        issuer: &str,
        is_ca: bool,
        mut extensions: Vec<Extension>,
        subject_key: &p256::ecdsa::SigningKey,
        issuer_key: &p256::ecdsa::SigningKey,
    ) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        use spki::{
            AlgorithmIdentifierOwned, ObjectIdentifier as SpkiOid, SubjectPublicKeyInfoOwned,
        };
        use std::str::FromStr;
        use x509_cert::{name::RdnSequence, serial_number::SerialNumber, Version};

        let verifying_key = subject_key.verifying_key();

        let subject = RdnSequence::from_str(subject).unwrap();
        let issuer = RdnSequence::from_str(issuer).unwrap();

        let not_before = x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_system_time(
                std::time::SystemTime::now() - std::time::Duration::from_secs(60),
            )
            .unwrap(),
        );
        let not_after = x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_system_time(
                std::time::SystemTime::now() + std::time::Duration::from_secs(365 * 24 * 60 * 60),
            )
            .unwrap(),
        );

        let validity = x509_cert::time::Validity {
            not_before,
            not_after,
        };

        // Add basic constraints if CA
        if is_ca {
            let bc_value = BASIC_CONSTRAINTS_CA_TRUE.to_vec();
            extensions.push(Extension {
                extn_id: BASIC_CONSTRAINTS_OID,
                critical: true,
                extn_value: OctetString::new(bc_value).unwrap(),
            });
        }

        let tbs_cert = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1, 2, 3, 4]).unwrap(),
            signature: AlgorithmIdentifierOwned {
                oid: SpkiOid::new_unwrap(&ECDSA_WITH_SHA256_OID.to_string()),
                parameters: None,
            },
            issuer,
            validity,
            subject,
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_key(*verifying_key).unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(Extensions::from(extensions))
            },
        };

        let tbs_der = tbs_cert.to_der().unwrap();
        let signature: p256::ecdsa::DerSignature = issuer_key.sign(&tbs_der);

        let cert = Certificate {
            tbs_certificate: tbs_cert,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: SpkiOid::new_unwrap(&ECDSA_WITH_SHA256_OID.to_string()),
                parameters: None,
            },
            signature: der::asn1::BitString::from_bytes(&signature.to_bytes()).unwrap(),
        };

        cert.to_der().unwrap()
    }

    fn create_test_certificate(
        subject: &str,
        issuer: &str,
        is_ca: bool,
        extensions: Vec<Extension>,
    ) -> Vec<u8> {
        use p256::ecdsa::SigningKey;
        let key = SigningKey::random(&mut rand::thread_rng());
        create_test_certificate_with_key(subject, issuer, is_ca, extensions, &key, &key)
    }

    fn create_test_precertificate_with_key(
        subject: &str,
        issuer: &str,
        subject_key: &p256::ecdsa::SigningKey,
        issuer_key: &p256::ecdsa::SigningKey,
    ) -> Vec<u8> {
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(ASN1_NULL.to_vec()).unwrap(),
        };

        create_test_certificate_with_key(
            subject,
            issuer,
            false,
            vec![poison_ext],
            subject_key,
            issuer_key,
        )
    }

    fn create_test_precertificate(subject: &str, issuer: &str) -> Vec<u8> {
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(ASN1_NULL.to_vec()).unwrap(),
        };

        create_test_certificate(subject, issuer, false, vec![poison_ext])
    }

    #[allow(dead_code)]
    fn create_precert_signing_certificate(subject: &str, issuer: &str) -> Vec<u8> {
        // Basic Constraints extension (CA:true)
        let bc_ext = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: OctetString::new(BASIC_CONSTRAINTS_CA_TRUE.to_vec()).unwrap(),
        };

        // Extended Key Usage with CT OID
        let eku_ext = Extension {
            extn_id: EXTENDED_KEY_USAGE_OID,
            critical: true,
            extn_value: OctetString::new(EKU_CT_ENCODED.to_vec()).unwrap(),
        };

        create_test_certificate(subject, issuer, false, vec![bc_ext, eku_ext])
    }

    // Helper function to create a validator for tests
    fn create_test_validator(config: Rfc6962ValidationConfig) -> Result<Rfc6962Validator> {
        use pem_rfc7468;

        let mut trusted_roots = Vec::new();

        // Load certificates from the configured directory
        if config.trusted_roots_dir.exists() {
            for entry in fs::read_dir(&config.trusted_roots_dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                    let pem_data = fs::read_to_string(&path).unwrap();
                    if let Ok((label, der_bytes)) = pem_rfc7468::decode_vec(pem_data.as_bytes()) {
                        if label == "CERTIFICATE" {
                            if let Ok(cert) = Certificate::from_der(&der_bytes) {
                                trusted_roots.push(cert);
                            }
                        }
                    }
                }
            }
        }

        Rfc6962Validator::with_trusted_roots(config, trusted_roots)
    }

    #[tokio::test]
    async fn test_validate_simple_certificate_chain() {
        use p256::ecdsa::SigningKey;

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let root_key = SigningKey::random(&mut rand::thread_rng());
        let ee_key = SigningKey::random(&mut rand::thread_rng());

        // Create a root certificate (self-signed)
        let root_cert = create_test_certificate_with_key(
            "CN=Test Root CA,O=Test Org",
            "CN=Test Root CA,O=Test Org",
            true,
            vec![],
            &root_key,
            &root_key, // Self-signed
        );

        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&root_cert);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        println!("Root certificate PEM:\n{}", root_pem);
        println!("Writing to: {:?}", roots_dir.join("root.pem"));
        fs::write(roots_dir.join("root.pem"), &root_pem).unwrap();

        let contents = fs::read_to_string(roots_dir.join("root.pem")).unwrap();
        println!("Read back: {} bytes", contents.len());

        // Create end-entity certificate signed by root
        let ee_cert = create_test_certificate_with_key(
            "CN=example.com",
            "CN=Test Root CA,O=Test Org",
            false,
            vec![],
            &ee_key,
            &root_key, // Signed by root
        );

        println!("Directory contents of {:?}:", roots_dir);
        for entry in fs::read_dir(&roots_dir).unwrap() {
            let entry = entry.unwrap();
            println!("  - {:?}", entry.path());
        }

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            max_chain_length: 10,
            allowed_signature_algorithms: vec![ECDSA_WITH_SHA256_OID.to_string()]
                .into_iter()
                .collect(),
            temporal_window: None,
            ccadb: CcadbEnvironment::Test,
        };

        let validator = create_test_validator(config).unwrap();

        println!(
            "Validator has {} trusted roots",
            validator.trusted_roots.len()
        );

        let chain = vec![ee_cert, root_cert];
        let result = validator.validate_chain(&chain).await;

        if let Err(e) = &result {
            println!("Validation error: {}", e);
        }

        assert!(
            result.is_ok(),
            "Valid certificate chain should pass validation"
        );
    }

    #[tokio::test]
    async fn test_validate_precertificate_chain() {
        use p256::ecdsa::SigningKey;

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let root_key = SigningKey::random(&mut rand::thread_rng());
        let precert_key = SigningKey::random(&mut rand::thread_rng());

        // Create a root certificate (self-signed)
        let root_cert = create_test_certificate_with_key(
            "CN=Test Root CA,O=Test Org",
            "CN=Test Root CA,O=Test Org",
            true,
            vec![],
            &root_key,
            &root_key, // Self-signed
        );

        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&root_cert);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        fs::write(roots_dir.join("root.pem"), root_pem).unwrap();

        // Create precertificate signed by root
        let precert = create_test_precertificate_with_key(
            "CN=example.com",
            "CN=Test Root CA,O=Test Org",
            &precert_key,
            &root_key, // Signed by root
        );

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            max_chain_length: 10,
            allowed_signature_algorithms: vec![ECDSA_WITH_SHA256_OID.to_string()]
                .into_iter()
                .collect(),
            temporal_window: None,
            ccadb: CcadbEnvironment::Test,
        };

        let validator = create_test_validator(config).unwrap();

        let chain = vec![precert, root_cert];
        let result = validator.validate_chain(&chain).await;

        if let Err(e) = &result {
            println!("Validation error: {}", e);
        }

        assert!(
            result.is_ok(),
            "Valid precertificate chain should pass validation"
        );
    }

    #[test]
    fn test_extract_issuer_key_hash() {
        let root_cert = create_test_certificate(
            "CN=Test Root CA,O=Test Org",
            "CN=Test Root CA,O=Test Org",
            true,
            vec![],
        );

        let precert = create_test_precertificate("CN=example.com", "CN=Test Root CA,O=Test Org");

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&root_cert);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        fs::write(roots_dir.join("root.pem"), root_pem).unwrap();

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir,
            temporal_window: None,
            ..Default::default()
        };
        let validator = create_test_validator(config).unwrap();

        let chain = vec![precert, root_cert];
        let result = validator.extract_issuer_key_hash(&chain);

        assert!(result.is_ok(), "Should be able to extract issuer key hash");
        let hash = result.unwrap();
        assert_eq!(hash.len(), 32, "Issuer key hash should be 32 bytes");
    }

    #[test]
    fn test_is_ca_certificate() {
        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        // Create a CA certificate
        let ca_cert_der = create_test_certificate(
            "CN=Test CA,O=Test Org",
            "CN=Test CA,O=Test Org",
            true, // is_ca = true
            vec![],
        );
        let ca_cert = Certificate::from_der(&ca_cert_der).unwrap();

        // Create an end-entity certificate
        let ee_cert_der = create_test_certificate(
            "CN=example.com",
            "CN=Test CA,O=Test Org",
            false, // is_ca = false
            vec![],
        );
        let ee_cert = Certificate::from_der(&ee_cert_der).unwrap();

        // Create a precert signing certificate (has CA:TRUE and CT EKU)
        let bc_value = BASIC_CONSTRAINTS_CA_TRUE.to_vec();
        let bc_ext = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: OctetString::new(bc_value).unwrap(),
        };

        let eku_value = ExtendedKeyUsage(vec![CT_EKU_OID]).to_der().unwrap();
        let eku_ext = Extension {
            extn_id: EXTENDED_KEY_USAGE_OID,
            critical: true,
            extn_value: OctetString::new(eku_value).unwrap(),
        };

        let precert_signing_cert_der = create_test_certificate(
            "CN=Precert Signing Cert",
            "CN=Test CA,O=Test Org",
            false, // Let extensions handle CA status
            vec![bc_ext, eku_ext],
        );
        let precert_signing_cert = Certificate::from_der(&precert_signing_cert_der).unwrap();

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir,
            ..Default::default()
        };
        let validator = create_test_validator(config).unwrap();

        // Test CA certificate
        assert!(
            validator.is_ca_certificate(&ca_cert),
            "CA certificate should be identified as CA"
        );

        // Test end-entity certificate
        assert!(
            !validator.is_ca_certificate(&ee_cert),
            "End-entity certificate should not be identified as CA"
        );

        // Test precert signing certificate (has CA:TRUE)
        assert!(
            validator.is_ca_certificate(&precert_signing_cert),
            "Precert signing certificate should be identified as CA"
        );
    }

    #[test]
    fn test_tbs_extraction() {
        let precert = create_test_precertificate("CN=example.com", "CN=Test CA");

        let ca_cert = create_test_certificate("CN=Test CA", "CN=Test CA", true, vec![]);

        let chain = vec![ca_cert];

        let result = TbsExtractor::extract_tbs_certificate(&precert, &chain);
        assert!(result.is_ok(), "Should be able to extract TBS certificate");

        let tbs = result.unwrap();

        let tbs_cert = TbsCertificate::from_der(&tbs).unwrap();

        // Check that poison extension is not present
        if let Some(extensions) = &tbs_cert.extensions {
            for ext in extensions.iter() {
                assert_ne!(
                    ext.extn_id, CT_POISON_EXTENSION_OID,
                    "Poison extension should be removed"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_verify_chain_to_root_signature() {
        use p256::ecdsa::SigningKey;

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let real_root_key = SigningKey::random(&mut rand::thread_rng());
        let fake_root_key = SigningKey::random(&mut rand::thread_rng());
        let ee_key = SigningKey::random(&mut rand::thread_rng());

        // Create the real root certificate (self-signed)
        let real_root_cert = create_test_certificate_with_key(
            "CN=Test Root CA,O=Test Org",
            "CN=Test Root CA,O=Test Org",
            true,
            vec![],
            &real_root_key,
            &real_root_key, // Self-signed
        );

        // Save real root certificate
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&real_root_cert);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        fs::write(roots_dir.join("root.pem"), root_pem).unwrap();

        // Create an end-entity certificate that CLAIMS to be signed by the root
        // but is actually signed by a different key (attack scenario)
        let malicious_ee_cert = create_test_certificate_with_key(
            "CN=evil.example.com",
            "CN=Test Root CA,O=Test Org", // Claims same issuer as trusted root
            false,
            vec![],
            &ee_key,
            &fake_root_key, // But signed by different key!
        );

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            max_chain_length: 10,
            allowed_signature_algorithms: vec![ECDSA_WITH_SHA256_OID.to_string()]
                .into_iter()
                .collect(),
            temporal_window: None,
            ccadb: CcadbEnvironment::Test,
        };

        let validator = create_test_validator(config).unwrap();

        // Test 1: Malicious chain should fail
        let malicious_chain = vec![malicious_ee_cert];
        let result = validator.validate_chain(&malicious_chain).await;
        assert!(
            result.is_err(),
            "Malicious certificate claiming false issuer should fail validation"
        );

        // Test 2: Create a properly signed certificate
        let valid_ee_cert = create_test_certificate_with_key(
            "CN=valid.example.com",
            "CN=Test Root CA,O=Test Org",
            false,
            vec![],
            &ee_key,
            &real_root_key, // Actually signed by the real root
        );

        let valid_chain = vec![valid_ee_cert];
        let result = validator.validate_chain(&valid_chain).await;
        assert!(
            result.is_ok(),
            "Valid certificate signed by trusted root should pass validation"
        );
    }

    #[tokio::test]
    async fn test_verify_chain_with_intermediate() {
        use p256::ecdsa::SigningKey;

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let root_key = SigningKey::random(&mut rand::thread_rng());
        let intermediate_key = SigningKey::random(&mut rand::thread_rng());
        let ee_key = SigningKey::random(&mut rand::thread_rng());

        // Create root certificate (self-signed)
        let root_cert = create_test_certificate_with_key(
            "CN=Test Root CA",
            "CN=Test Root CA",
            true,
            vec![],
            &root_key,
            &root_key,
        );

        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&root_cert);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        fs::write(roots_dir.join("root.pem"), root_pem).unwrap();

        // Create intermediate certificate signed by root
        let intermediate_cert = create_test_certificate_with_key(
            "CN=Test Intermediate CA",
            "CN=Test Root CA",
            true,
            vec![],
            &intermediate_key,
            &root_key,
        );

        // Create end-entity certificate signed by intermediate
        let ee_cert = create_test_certificate_with_key(
            "CN=example.com",
            "CN=Test Intermediate CA",
            false,
            vec![],
            &ee_key,
            &intermediate_key,
        );

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            max_chain_length: 10,
            allowed_signature_algorithms: vec![ECDSA_WITH_SHA256_OID.to_string()]
                .into_iter()
                .collect(),
            temporal_window: None,
            ccadb: CcadbEnvironment::Test,
        };
        let validator = create_test_validator(config).unwrap();

        // Test 1: Chain without root should succeed (intermediate chains to trusted root)
        let chain_without_root = vec![ee_cert.clone(), intermediate_cert.clone()];
        let result = validator.validate_chain(&chain_without_root).await;
        assert!(
            result.is_ok(),
            "Chain with intermediate signed by trusted root should pass: {:?}",
            result
        );

        // Test 2: Chain with root included should also succeed
        let chain_with_root = vec![
            ee_cert.clone(),
            intermediate_cert.clone(),
            root_cert.clone(),
        ];
        let result = validator.validate_chain(&chain_with_root).await;
        assert!(
            result.is_ok(),
            "Chain including the trusted root should pass: {:?}",
            result
        );

        // Test 3: Incomplete chain (missing intermediate) should fail
        let incomplete_chain = vec![ee_cert.clone()];
        let result = validator.validate_chain(&incomplete_chain).await;
        assert!(
            result.is_err(),
            "Incomplete chain missing intermediate should fail"
        );
    }

    #[tokio::test]
    async fn test_chain_termination_attack() {
        use p256::ecdsa::SigningKey;

        // This test demonstrates a vulnerability where an attacker can append
        // certificates after a valid intermediate

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let real_root_key = SigningKey::random(&mut rand::thread_rng());
        let intermediate_key = SigningKey::random(&mut rand::thread_rng());
        let attacker_root_key = SigningKey::random(&mut rand::thread_rng());
        let attacker_ee_key = SigningKey::random(&mut rand::thread_rng());

        // Create the real root certificate
        let real_root_cert = create_test_certificate_with_key(
            "CN=Real Trusted Root",
            "CN=Real Trusted Root",
            true,
            vec![],
            &real_root_key,
            &real_root_key,
        );

        // Save real root
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&real_root_cert);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        fs::write(roots_dir.join("root.pem"), root_pem).unwrap();

        // Create a valid intermediate signed by the real root
        let valid_intermediate = create_test_certificate_with_key(
            "CN=Valid Intermediate",
            "CN=Real Trusted Root",
            true,
            vec![],
            &intermediate_key,
            &real_root_key, // Properly signed by real root
        );

        // Create attacker's fake root (self-signed)
        let attacker_root = create_test_certificate_with_key(
            "CN=Attacker Fake Root",
            "CN=Attacker Fake Root",
            true,
            vec![],
            &attacker_root_key,
            &attacker_root_key,
        );

        // Create attacker's end-entity cert signed by the VALID intermediate
        // (This simulates stolen intermediate key or other compromise)
        let attacker_ee = create_test_certificate_with_key(
            "CN=attacker.evil.com",
            "CN=Valid Intermediate",
            false,
            vec![],
            &attacker_ee_key,
            &intermediate_key, // Signed by valid intermediate
        );

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            max_chain_length: 10,
            allowed_signature_algorithms: vec![ECDSA_WITH_SHA256_OID.to_string()]
                .into_iter()
                .collect(),
            temporal_window: None,
            ccadb: CcadbEnvironment::Test,
        };
        let validator = create_test_validator(config).unwrap();

        // Test 1: Attack chain with fake root included
        let attack_chain_with_fake_root = vec![
            attacker_ee.clone(),
            valid_intermediate.clone(),
            attacker_root,
        ];
        let result = validator.validate_chain(&attack_chain_with_fake_root).await;
        assert!(result.is_err(), "Attack chain with fake root should fail");

        // Test 2: What if attacker just omits their fake root?
        // Chain: [Attacker EE] -> [Valid Intermediate]
        // The intermediate IS signed by a trusted root, but the EE is signed by intermediate
        let attack_chain_without_fake_root = vec![attacker_ee, valid_intermediate];
        let result2 = validator
            .validate_chain(&attack_chain_without_fake_root)
            .await;

        // This should succeed because it's a valid chain to a trusted root
        assert!(
            result2.is_ok(),
            "Valid chain should succeed even if EE was signed by compromised intermediate"
        );
    }

    #[tokio::test]
    async fn test_disconnected_chain_vulnerability() {
        use p256::ecdsa::SigningKey;

        // Test for a disconnected chain where a trusted root is present
        // but not actually connected to the end-entity certificate

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let trusted_root_key = SigningKey::random(&mut rand::thread_rng());
        let attacker_ca_key = SigningKey::random(&mut rand::thread_rng());
        let attacker_ee_key = SigningKey::random(&mut rand::thread_rng());

        // Create trusted root
        let trusted_root = create_test_certificate_with_key(
            "CN=Trusted Root",
            "CN=Trusted Root",
            true,
            vec![],
            &trusted_root_key,
            &trusted_root_key,
        );

        // Save trusted root
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&trusted_root);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        fs::write(roots_dir.join("root.pem"), root_pem).unwrap();

        // Create attacker's CA (NOT signed by trusted root)
        let attacker_ca = create_test_certificate_with_key(
            "CN=Attacker CA",
            "CN=Attacker CA",
            true,
            vec![],
            &attacker_ca_key,
            &attacker_ca_key, // Self-signed
        );

        // Create attacker's EE signed by attacker's CA
        let attacker_ee = create_test_certificate_with_key(
            "CN=attacker.com",
            "CN=Attacker CA",
            false,
            vec![],
            &attacker_ee_key,
            &attacker_ca_key,
        );

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            max_chain_length: 10,
            allowed_signature_algorithms: vec![ECDSA_WITH_SHA256_OID.to_string()]
                .into_iter()
                .collect(),
            temporal_window: None,
            ccadb: CcadbEnvironment::Test,
        };
        let validator = create_test_validator(config).unwrap();

        // Test: Disconnected chain
        // [Attacker EE] -> [Attacker CA] -> [Trusted Root]
        // But Attacker CA is NOT signed by Trusted Root!
        let disconnected_chain = vec![attacker_ee, attacker_ca, trusted_root.clone()];

        let result = validator.validate_chain(&disconnected_chain).await;

        assert!(result.is_err(), "Disconnected chain should fail validation");
    }

    #[tokio::test]
    async fn test_temporal_window_validation() {
        use p256::ecdsa::SigningKey;

        let temp_dir = TempDir::new().unwrap();
        let roots_dir = temp_dir.path().join("roots");
        fs::create_dir(&roots_dir).unwrap();

        let root_key = SigningKey::random(&mut rand::thread_rng());
        let ee_key = SigningKey::random(&mut rand::thread_rng());

        // Create root certificate
        let root_cert = create_test_certificate_with_key(
            "CN=Test Root CA",
            "CN=Test Root CA",
            true,
            vec![],
            &root_key,
            &root_key,
        );

        let root_b64 = base64::engine::general_purpose::STANDARD.encode(&root_cert);
        let mut root_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in root_b64.as_bytes().chunks(64) {
            root_pem.push_str(&String::from_utf8_lossy(chunk));
            root_pem.push('\n');
        }
        root_pem.push_str("-----END CERTIFICATE-----\n");
        fs::write(roots_dir.join("root.pem"), root_pem).unwrap();

        // Create end-entity certificate signed by root
        let ee_cert = create_test_certificate_with_key(
            "CN=example.com",
            "CN=Test Root CA",
            false,
            vec![],
            &ee_key,
            &root_key,
        );

        // Create a config with a temporal window that should include the certificate's expiry
        // Assuming the test certificate is valid for 1 year from now
        let window_start = Utc::now();
        let window_end = Utc::now() + chrono::Duration::days(400); // Wide enough to include cert expiry

        let config = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            temporal_window: Some(TemporalWindow {
                start: window_start,
                end: window_end,
            }),
            ..Default::default()
        };

        let validator = create_test_validator(config).unwrap();

        // Test 1: Certificate that expires within the temporal window (should pass)
        let chain = vec![ee_cert.clone(), root_cert.clone()];
        let result = validator.validate_chain(&chain).await;
        assert!(
            result.is_ok(),
            "Certificate expiring within temporal window should pass: {:?}",
            result
        );

        // Test 2: Certificate that expires before window start (should fail)
        let config_future = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            temporal_window: Some(TemporalWindow {
                start: Utc::now() + chrono::Duration::days(500), // Start after cert expires
                end: Utc::now() + chrono::Duration::days(730),
            }),
            ..Default::default()
        };

        let validator_future = create_test_validator(config_future).unwrap();
        let result = validator_future.validate_chain(&chain).await;
        assert!(
            result.is_err(),
            "Certificate expiring before temporal window should fail"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("expires before log temporal window starts"),
            "Error message should mention certificate expires before window: {}",
            err_msg
        );

        // Test 3: Certificate that expires after window end (should fail)
        let config_past = Rfc6962ValidationConfig {
            trusted_roots_dir: roots_dir.clone(),
            temporal_window: Some(TemporalWindow {
                start: Utc::now() - chrono::Duration::days(100),
                end: Utc::now() + chrono::Duration::days(30), // End before cert expires
            }),
            ..Default::default()
        };

        let validator_past = create_test_validator(config_past).unwrap();
        let result = validator_past.validate_chain(&chain).await;
        assert!(
            result.is_err(),
            "Certificate expiring after temporal window should fail"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("expires outside log temporal window"),
            "Error message should mention certificate expires outside window: {}",
            err_msg
        );
    }
}
