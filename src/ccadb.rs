use crate::types::{CtError, Result};
use crate::validation::CcadbEnvironment;
use csv::Reader;
use der::{Decode, Encode};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use x509_cert::Certificate;

/// A single root certificate entry from CCADB
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CcadbRootEntry {
    pub subject: String,
    pub ca_owner: String,
    pub certificate: Certificate,
    pub sha256_fingerprint: String,
}

/// Shared root certificate store
#[derive(Debug, Clone)]
pub struct RootCertificateStore {
    /// Map from SHA256 fingerprint to certificate
    certificates: Arc<RwLock<HashMap<String, CcadbRootEntry>>>,
}

impl RootCertificateStore {
    pub fn new() -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load certificates from the trusted_roots directory (flat structure)
    pub async fn load_from_directory(&self, dir: &Path) -> Result<()> {
        use std::fs;

        if !dir.exists() {
            return Ok(());
        }

        let mut certs = self.certificates.write().await;
        let mut loaded_count = 0;

        for entry in fs::read_dir(dir)
            .map_err(|e| CtError::Internal(format!("Failed to read directory {:?}: {}", dir, e)))?
        {
            let entry = entry
                .map_err(|e| CtError::Internal(format!("Failed to read directory entry: {}", e)))?;

            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("pem") {
                match self.load_pem_certificate(&path) {
                    Ok((cert, fingerprint)) => {
                        let entry = CcadbRootEntry {
                            subject: cert.tbs_certificate.subject.to_string(),
                            ca_owner: "Local".to_string(),
                            certificate: cert,
                            sha256_fingerprint: fingerprint.clone(),
                        };
                        if !certs.contains_key(&fingerprint) {
                            certs.insert(fingerprint.clone(), entry);
                            loaded_count += 1;
                            tracing::trace!(
                                "Loaded certificate from {:?} with fingerprint {}",
                                path,
                                &fingerprint[0..16]
                            );
                        } else {
                            tracing::trace!(
                                "Certificate from {:?} already exists with fingerprint {}",
                                path,
                                &fingerprint[0..16]
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load certificate from {:?}: {}", path, e);
                    }
                }
            }
        }

        tracing::debug!(
            "Loaded {} certificates from directory {:?}",
            loaded_count,
            dir
        );
        Ok(())
    }

    fn load_pem_certificate(&self, path: &Path) -> Result<(Certificate, String)> {
        use sha2::{Digest, Sha256};
        use std::fs;

        let pem_data = fs::read_to_string(path)
            .map_err(|e| CtError::Internal(format!("Failed to read PEM file {:?}: {}", path, e)))?;

        let (label, der_bytes) = pem_rfc7468::decode_vec(pem_data.as_bytes()).map_err(|e| {
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

        // Calculate SHA256 fingerprint
        let mut hasher = Sha256::new();
        hasher.update(&der_bytes);
        let fingerprint = hex::encode(hasher.finalize()).to_uppercase();

        Ok((cert, fingerprint))
    }

    /// Add certificates from CCADB CSV data (additive only)
    pub async fn add_from_ccadb_csv(&self, csv_data: &str) -> Result<()> {
        use sha2::{Digest, Sha256};

        let mut reader = Reader::from_reader(csv_data.as_bytes());
        let mut certs = self.certificates.write().await;
        let mut added_count = 0;
        let mut duplicate_count = 0;

        for result in reader.records() {
            let record = result
                .map_err(|e| CtError::Internal(format!("Failed to parse CSV record: {}", e)))?;

            // Extract fields by index
            let subject = record.get(0).unwrap_or("").to_string();
            let ca_owner = record.get(1).unwrap_or("").to_string();
            let pem_cert = record.get(2).unwrap_or("");
            let sha256_fingerprint = record.get(3).unwrap_or("").to_string();

            if pem_cert.is_empty() {
                continue;
            }

            // Clean up the PEM certificate data
            // Remove any tabs, carriage returns, and trim whitespace
            let cleaned_pem = pem_cert
                .replace('\t', "")
                .replace('\r', "")
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join("\n");

            // Ensure PEM has proper markers
            let cleaned_pem = if !cleaned_pem.starts_with("-----BEGIN") {
                if cleaned_pem.contains("-----END CERTIFICATE-----") {
                    format!("-----BEGIN CERTIFICATE-----\n{}", cleaned_pem)
                } else {
                    tracing::warn!("PEM data for {} missing proper markers", subject);
                    continue;
                }
            } else {
                cleaned_pem
            };

            match pem_rfc7468::decode_vec(cleaned_pem.as_bytes()) {
                Ok((label, der_bytes)) if label == "CERTIFICATE" => {
                    match Certificate::from_der(&der_bytes) {
                        Ok(cert) => {
                            let mut hasher = Sha256::new();
                            hasher.update(&der_bytes);
                            let calculated_fingerprint =
                                hex::encode(hasher.finalize()).to_uppercase();
                            let provided_fingerprint =
                                sha256_fingerprint.replace(':', "").to_uppercase();

                            if calculated_fingerprint != provided_fingerprint {
                                tracing::warn!(
                                    "Fingerprint mismatch for {}: calculated {} vs provided {}",
                                    subject,
                                    calculated_fingerprint,
                                    provided_fingerprint
                                );
                                continue;
                            }

                            let entry = CcadbRootEntry {
                                subject: subject.clone(),
                                ca_owner,
                                certificate: cert,
                                sha256_fingerprint: calculated_fingerprint.clone(),
                            };

                            // Only insert if not already present (additive only)
                            if certs.contains_key(&calculated_fingerprint) {
                                duplicate_count += 1;
                                tracing::trace!(
                                    "Certificate {} already exists with fingerprint {}",
                                    subject,
                                    &calculated_fingerprint[0..16]
                                );
                            } else {
                                certs.insert(calculated_fingerprint.clone(), entry);
                                added_count += 1;
                                tracing::trace!(
                                    "Added certificate {} with fingerprint {}",
                                    subject,
                                    &calculated_fingerprint[0..16]
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse certificate for {}: {}", subject, e);
                        }
                    }
                }
                Ok((label, _)) => {
                    tracing::warn!(
                        "Invalid PEM label for {}: expected CERTIFICATE, got {}",
                        subject,
                        label
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse PEM for {}: {}. PEM length: {}, starts with: {:?}",
                        subject,
                        e,
                        cleaned_pem.len(),
                        cleaned_pem.chars().take(50).collect::<String>()
                    );
                }
            }
        }

        tracing::debug!(
            "CCADB CSV processing complete: {} added, {} duplicates skipped",
            added_count,
            duplicate_count
        );
        Ok(())
    }

    /// Get all certificates as a vector
    pub async fn get_all_certificates(&self) -> Vec<Certificate> {
        self.certificates
            .read()
            .await
            .values()
            .map(|entry| entry.certificate.clone())
            .collect()
    }

    /// Get certificate count
    pub async fn count(&self) -> usize {
        self.certificates.read().await.len()
    }

    /// Write certificates to disk (flat structure)
    pub async fn persist_to_directory(&self, dir: &Path) -> Result<()> {
        use std::fs;

        fs::create_dir_all(dir).map_err(|e| {
            CtError::Internal(format!("Failed to create directory {:?}: {}", dir, e))
        })?;

        let certs = self.certificates.read().await;

        for (fingerprint, entry) in certs.iter() {
            let filename = format!("{}.pem", &fingerprint[0..16]);
            let path = dir.join(&filename);

            if path.exists() {
                continue;
            }

            let der_bytes = entry
                .certificate
                .to_der()
                .map_err(|e| CtError::Internal(format!("Failed to encode certificate: {}", e)))?;

            let pem = pem_rfc7468::encode_string(
                "CERTIFICATE",
                pem_rfc7468::LineEnding::LF,
                der_bytes.as_slice(),
            )
            .map_err(|e| CtError::Internal(format!("Failed to encode PEM: {}", e)))?;

            fs::write(&path, pem).map_err(|e| {
                CtError::Internal(format!("Failed to write certificate to {:?}: {}", path, e))
            })?;
        }

        Ok(())
    }
}

/// Worker that fetches and updates CCADB root certificates
pub struct CcadbWorker {
    environment: CcadbEnvironment,
    store: RootCertificateStore,
    trusted_roots_dir: std::path::PathBuf,
}

impl CcadbWorker {
    pub fn new(
        environment: CcadbEnvironment,
        store: RootCertificateStore,
        trusted_roots_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            environment,
            store,
            trusted_roots_dir,
        }
    }

    /// Fetch and update root certificates from CCADB
    pub async fn update(&self) -> Result<()> {
        tracing::info!(
            "Fetching CCADB root certificates from {:?}",
            self.environment
        );

        let url = self.environment.url();
        let response = reqwest::get(url)
            .await
            .map_err(|e| CtError::Internal(format!("Failed to fetch CCADB data: {}", e)))?;

        if !response.status().is_success() {
            return Err(CtError::Internal(format!(
                "CCADB request failed with status: {}",
                response.status()
            )));
        }

        let csv_data = response
            .text()
            .await
            .map_err(|e| CtError::Internal(format!("Failed to read CCADB response: {}", e)))?;

        self.store.add_from_ccadb_csv(&csv_data).await?;

        self.store
            .persist_to_directory(&self.trusted_roots_dir)
            .await?;

        tracing::info!(
            "Successfully updated CCADB roots. Total certificates: {}",
            self.store.count().await
        );

        Ok(())
    }

    /// Run the worker periodically
    pub async fn run_periodic(self, interval: std::time::Duration) {
        let mut interval = tokio::time::interval(interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            if let Err(e) = self.update().await {
                tracing::error!("CCADB update failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Real CCADB test data from the Test environment
    const TEST_CCADB_CSV: &str = r#""Subject","CA Owner","X.509 Certificate (PEM)","SHA-256 Fingerprint","Intended Use Case(s) Served","CCADB Inclusion Request Case #","Apple Requested?","Google Chrome Requested?","Mozilla Requested?"
"CN=TunTrust Root CA; O=Agence Nationale de Certification Electronique; C=TN","Agence Nationale de Certification Electronique","-----BEGIN CERTIFICATE-----
MIIFszCCA5ugAwIBAgIUEwLV4kBMkkaGFmddtLu7sms+/BMwDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVE4xNzA1BgNVBAoMLkFnZW5jZSBOYXRpb25hbGUgZGUg
Q2VydGlmaWNhdGlvbiBFbGVjdHJvbmlxdWUxGTAXBgNVBAMMEFR1blRydXN0IFJv
b3QgQ0EwHhcNMTkwNDI2MDg1NzU2WhcNNDQwNDI2MDg1NzU2WjBhMQswCQYDVQQG
EwJUTjE3MDUGA1UECgwuQWdlbmNlIE5hdGlvbmFsZSBkZSBDZXJ0aWZpY2F0aW9u
IEVsZWN0cm9uaXF1ZTEZMBcGA1UEAwwQVHVuVHJ1c3QgUm9vdCBDQTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMPN0/y9BFPdDCA61YguBUtB9YOCfvdZ
n56eY+hz2vYGqU8ftPkLHzmMmiDQfgbU7DTZhrx1W4eI8NLZ1KMKsmwb60ksPqxd
2JQDoOw05TDENX37Jk0bbjBU2PWARZw5rZzJJQRNmpA+TkBuimvNKWfGzC3gdOgF
VwpIUPp6Q9p+7FuaDmJ2/uqdHYVy7BG7NegfJ7/Boce7SBbdVtfMTqDhuazb1YMZ
GoXRlJfXyqNlC/M4+QKu3fZnz8k/9YosRxqZbwUN/dAdgjH8KcwAWJeRTIAAHDOF
li/LQcKLEITDCSSJH7UP2dl3RxiSlGBcx5kDPP73lad9UKGAwqmDrViWVSHbhlnU
r8a83YFuB9tgYv7sEG7aaAH0gxupPqJbI9dkxt/con3YS7qC0lH4Zr8GRuR5KiY2
eY8fTpkdso8MDhz/yV3A/ZAQprE38806JG60hZC/gLkMjNWb1sjxVj8agIl6qeIb
MlEsPvLfe/ZdeikZjuXIvTZxi11Mwh0/rViizz1wTaZQmCXcI/m4WEEIcb9PuISg
jwBUFfyRbVinljvrS5YnzWuioYasDXxU5mZMZl+QviGaAkYt5IPCgLnPSz7ofzwB
7I9ezX/SKEIBlYrilz0QIX32nRzFNKHsLA4KUiwSVXAkPcvCFDVDXSdOvsC9qnyW
5/yeYa1E0wCXAgMBAAGjYzBhMB0GA1UdDgQWBBQGmpsfU33x9aTI04Y+oXNZtPdE
ITAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFAaamx9TffH1pMjThj6hc1m0
90QhMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAqgVutt0Vyb+z
xiD2BkewhpMl0425yAA/l/VSJ4hxyXT968pk21vvHl26v9Hr7lxpuhbI87mP0zYu
QEkHDVneixCwSQXi/5E/S7fdAo74gShczNxtr18UnH1YeA32gAm56Q6XKRm4t+v4
FstVEuTGfbvE7Pi1HE4+Z7/FXxttbUcoqgRYYdZ2vyJ/0Adqp2RT8JeNnYA/u8EH
22Wv5psymsNUk8QcCMNE+3tjEUPRahphanltkE8pjkcFwRJpadbGNjHh/PqAulxP
xOu3Mqz4dWEX1xAZufHSCe96Qp1bWgvUxpVOKs7/B9dPfhgGiPEZtdmYu65xxBzn
dFlY7wyJz4sfdZMaBBSSSFCp61cpABbjNhzI+L/wM9VBD8TMPN3pM0MBkRArHtG5
Xc0yGYuPjCB31yLEQtyEFpslbei0VXF/sHyz03FJuc9SpAQ/3D2gu68zngowYI7b
nV2UqL1g52KAdoGDDIzMMEZJ4gzSqK/rYXHv5yJiqfdcZGyfFoxnNidF9Ql7v/YQ
CvGwjVRDjAS6oz/v4jXH+XTgbzRB0L9zZVcg+ZtnemZoJE6AZb0QmQZZ8mWvuMZH
u/2QeItBcy6vVR/cO5JyboTT0GFMDcx2V+IthSIVNg3rAZ3r2OvEhJn7wAzMMujj
d9qDRIueVSjAi1jTkD5OGwDxFa2DK5o=
-----END CERTIFICATE-----","2E44102AB58CB85419451C8E19D9ACF3662CAFBC614B6A53960A30F7D0E2EB41","Server Authentication (TLS) 1.3.6.1.5.5.7.3.1;Client Authentication 1.3.6.1.5.5.7.3.2","00002172","true","false","false"
"CN=Amazon ECDSA 256 Root EU M1; O=Amazon; C=DE","Amazon Trust Services","-----BEGIN CERTIFICATE-----
MIIB6zCCAZKgAwIBAgITB8DNiWzLnBYEbBghpkxseyndPzAKBggqhkjOPQQDAjBE
MQswCQYDVQQGEwJERTEPMA0GA1UEChMGQW1hem9uMSQwIgYDVQQDExtBbWF6b24g
RUNEU0EgMjU2IFJvb3QgRVUgTTEwHhcNMjQxMTE0MTI0NTUxWhcNNDIxMTE0MTI0
NTUxWjBEMQswCQYDVQQGEwJERTEPMA0GA1UEChMGQW1hem9uMSQwIgYDVQQDExtB
bWF6b24gRUNEU0EgMjU2IFJvb3QgRVUgTTEwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARmbxff3h/YNyAeVXPAGoZhLNYsm62QAp8CTvIe4oVUWR8Yp6QvaKMG7epW
J6x3NeQeqnYYfv6xiDy9nBfRkfWXo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHQ4EFgQUcdF/ctm4GS3wEaXNtYZPbh/d5aIwHwYDVR0j
BBgwFoAUcdF/ctm4GS3wEaXNtYZPbh/d5aIwCgYIKoZIzj0EAwIDRwAwRAIgJTtJ
A4US1mx9ZUncHr8Nh6LWLI55Z8hHlbGBErijvmMCIBHZnyKPmCfaHzy751ykNFdi
g3REnz9NPIRxUcunDvcv
-----END CERTIFICATE-----","9EAD32C9285FE68BA2C5B0FE427D149B103FDFA1D0958D77C3DA0FF246E853D3","Server Authentication (TLS) 1.3.6.1.5.5.7.3.1;Client Authentication 1.3.6.1.5.5.7.3.2","00002242","true","true","true"
"CN=Invalid Cert,O=Bad Org","Bad CA","NOT A VALID CERTIFICATE","AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF","Server Authentication","00000000","false","false","false"
"#;

    #[tokio::test]
    async fn test_root_store_new() {
        let store = RootCertificateStore::new();
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn test_add_from_ccadb_csv() {
        let store = RootCertificateStore::new();

        store.add_from_ccadb_csv(TEST_CCADB_CSV).await.unwrap();

        // Should have 2 valid certificates (the third one is invalid)
        assert_eq!(store.count().await, 2);

        let certs = store.get_all_certificates().await;
        assert_eq!(certs.len(), 2);
    }

    #[tokio::test]
    async fn test_additive_only_behavior() {
        let store = RootCertificateStore::new();

        // Add initial certificates
        store.add_from_ccadb_csv(TEST_CCADB_CSV).await.unwrap();
        let initial_count = store.count().await;
        assert_eq!(initial_count, 2); // Should have 2 valid certificates

        // Add the same CSV data again
        store.add_from_ccadb_csv(TEST_CCADB_CSV).await.unwrap();

        // Count should remain the same (no duplicates)
        assert_eq!(store.count().await, initial_count);

        // Create CSV with just one of the existing certificates
        let one_cert_csv = r#""Subject","CA Owner","X.509 Certificate (PEM)","SHA-256 Fingerprint","Intended Use Case(s) Served","CCADB Inclusion Request Case #","Apple Requested?","Google Chrome Requested?","Mozilla Requested?"
"CN=TunTrust Root CA; O=Agence Nationale de Certification Electronique; C=TN","Agence Nationale de Certification Electronique","-----BEGIN CERTIFICATE-----
MIIFszCCA5ugAwIBAgIUEwLV4kBMkkaGFmddtLu7sms+/BMwDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVE4xNzA1BgNVBAoMLkFnZW5jZSBOYXRpb25hbGUgZGUg
Q2VydGlmaWNhdGlvbiBFbGVjdHJvbmlxdWUxGTAXBgNVBAMMEFR1blRydXN0IFJv
b3QgQ0EwHhcNMTkwNDI2MDg1NzU2WhcNNDQwNDI2MDg1NzU2WjBhMQswCQYDVQQG
EwJUTjE3MDUGA1UECgwuQWdlbmNlIE5hdGlvbmFsZSBkZSBDZXJ0aWZpY2F0aW9u
IEVsZWN0cm9uaXF1ZTEZMBcGA1UEAwwQVHVuVHJ1c3QgUm9vdCBDQTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMPN0/y9BFPdDCA61YguBUtB9YOCfvdZ
n56eY+hz2vYGqU8ftPkLHzmMmiDQfgbU7DTZhrx1W4eI8NLZ1KMKsmwb60ksPqxd
2JQDoOw05TDENX37Jk0bbjBU2PWARZw5rZzJJQRNmpA+TkBuimvNKWfGzC3gdOgF
VwpIUPp6Q9p+7FuaDmJ2/uqdHYVy7BG7NegfJ7/Boce7SBbdVtfMTqDhuazb1YMZ
GoXRlJfXyqNlC/M4+QKu3fZnz8k/9YosRxqZbwUN/dAdgjH8KcwAWJeRTIAAHDOF
li/LQcKLEITDCSSJH7UP2dl3RxiSlGBcx5kDPP73lad9UKGAwqmDrViWVSHbhlnU
r8a83YFuB9tgYv7sEG7aaAH0gxupPqJbI9dkxt/con3YS7qC0lH4Zr8GRuR5KiY2
eY8fTpkdso8MDhz/yV3A/ZAQprE38806JG60hZC/gLkMjNWb1sjxVj8agIl6qeIb
MlEsPvLfe/ZdeikZjuXIvTZxi11Mwh0/rViizz1wTaZQmCXcI/m4WEEIcb9PuISg
jwBUFfyRbVinljvrS5YnzWuioYasDXxU5mZMZl+QviGaAkYt5IPCgLnPSz7ofzwB
7I9ezX/SKEIBlYrilz0QIX32nRzFNKHsLA4KUiwSVXAkPcvCFDVDXSdOvsC9qnyW
5/yeYa1E0wCXAgMBAAGjYzBhMB0GA1UdDgQWBBQGmpsfU33x9aTI04Y+oXNZtPdE
ITAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFAaamx9TffH1pMjThj6hc1m0
90QhMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAqgVutt0Vyb+z
xiD2BkewhpMl0425yAA/l/VSJ4hxyXT968pk21vvHl26v9Hr7lxpuhbI87mP0zYu
QEkHDVneixCwSQXi/5E/S7fdAo74gShczNxtr18UnH1YeA32gAm56Q6XKRm4t+v4
FstVEuTGfbvE7Pi1HE4+Z7/FXxttbUcoqgRYYdZ2vyJ/0Adqp2RT8JeNnYA/u8EH
22Wv5psymsNUk8QcCMNE+3tjEUPRahphanltkE8pjkcFwRJpadbGNjHh/PqAulxP
xOu3Mqz4dWEX1xAZufHSCe96Qp1bWgvUxpVOKs7/B9dPfhgGiPEZtdmYu65xxBzn
dFlY7wyJz4sfdZMaBBSSSFCp61cpABbjNhzI+L/wM9VBD8TMPN3pM0MBkRArHtG5
Xc0yGYuPjCB31yLEQtyEFpslbei0VXF/sHyz03FJuc9SpAQ/3D2gu68zngowYI7b
nV2UqL1g52KAdoGDDIzMMEZJ4gzSqK/rYXHv5yJiqfdcZGyfFoxnNidF9Ql7v/YQ
CvGwjVRDjAS6oz/v4jXH+XTgbzRB0L9zZVcg+ZtnemZoJE6AZb0QmQZZ8mWvuMZH
u/2QeItBcy6vVR/cO5JyboTT0GFMDcx2V+IthSIVNg3rAZ3r2OvEhJn7wAzMMujj
d9qDRIueVSjAi1jTkD5OGwDxFa2DK5o=
-----END CERTIFICATE-----","2E44102AB58CB85419451C8E19D9ACF3662CAFBC614B6A53960A30F7D0E2EB41","Server Authentication (TLS) 1.3.6.1.5.5.7.3.1;Client Authentication 1.3.6.1.5.5.7.3.2","00002172","true","false","false"
"#;

        store.add_from_ccadb_csv(one_cert_csv).await.unwrap();

        // Count should still be 2 (we don't remove certificates)
        assert_eq!(store.count().await, initial_count);

        // Now test with an empty CSV (header only)
        let empty_csv = r#""Subject","CA Owner","X.509 Certificate (PEM)","SHA-256 Fingerprint","Intended Use Case(s) Served","CCADB Inclusion Request Case #","Apple Requested?","Google Chrome Requested?","Mozilla Requested?"
"#;

        store.add_from_ccadb_csv(empty_csv).await.unwrap();

        // Count should still be 2 (we don't remove certificates)
        assert_eq!(store.count().await, initial_count);
    }

    #[tokio::test]
    async fn test_fingerprint_validation() {
        let store = RootCertificateStore::new();

        // Create CSV with mismatched fingerprint - using TunTrust cert with wrong fingerprint
        let bad_csv = r#""Subject","CA Owner","X.509 Certificate (PEM)","SHA-256 Fingerprint","Intended Use Case(s) Served","CCADB Inclusion Request Case #","Apple Requested?","Google Chrome Requested?","Mozilla Requested?"
"CN=TunTrust Root CA; O=Agence Nationale de Certification Electronique; C=TN","Agence Nationale de Certification Electronique","-----BEGIN CERTIFICATE-----
MIIFszCCA5ugAwIBAgIUEwLV4kBMkkaGFmddtLu7sms+/BMwDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVE4xNzA1BgNVBAoMLkFnZW5jZSBOYXRpb25hbGUgZGUg
Q2VydGlmaWNhdGlvbiBFbGVjdHJvbmlxdWUxGTAXBgNVBAMMEFR1blRydXN0IFJv
b3QgQ0EwHhcNMTkwNDI2MDg1NzU2WhcNNDQwNDI2MDg1NzU2WjBhMQswCQYDVQQG
EwJUTjE3MDUGA1UECgwuQWdlbmNlIE5hdGlvbmFsZSBkZSBDZXJ0aWZpY2F0aW9u
IEVsZWN0cm9uaXF1ZTEZMBcGA1UEAwwQVHVuVHJ1c3QgUm9vdCBDQTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMPN0/y9BFPdDCA61YguBUtB9YOCfvdZ
n56eY+hz2vYGqU8ftPkLHzmMmiDQfgbU7DTZhrx1W4eI8NLZ1KMKsmwb60ksPqxd
2JQDoOw05TDENX37Jk0bbjBU2PWARZw5rZzJJQRNmpA+TkBuimvNKWfGzC3gdOgF
VwpIUPp6Q9p+7FuaDmJ2/uqdHYVy7BG7NegfJ7/Boce7SBbdVtfMTqDhuazb1YMZ
GoXRlJfXyqNlC/M4+QKu3fZnz8k/9YosRxqZbwUN/dAdgjH8KcwAWJeRTIAAHDOF
li/LQcKLEITDCSSJH7UP2dl3RxiSlGBcx5kDPP73lad9UKGAwqmDrViWVSHbhlnU
r8a83YFuB9tgYv7sEG7aaAH0gxupPqJbI9dkxt/con3YS7qC0lH4Zr8GRuR5KiY2
eY8fTpkdso8MDhz/yV3A/ZAQprE38806JG60hZC/gLkMjNWb1sjxVj8agIl6qeIb
MlEsPvLfe/ZdeikZjuXIvTZxi11Mwh0/rViizz1wTaZQmCXcI/m4WEEIcb9PuISg
jwBUFfyRbVinljvrS5YnzWuioYasDXxU5mZMZl+QviGaAkYt5IPCgLnPSz7ofzwB
7I9ezX/SKEIBlYrilz0QIX32nRzFNKHsLA4KUiwSVXAkPcvCFDVDXSdOvsC9qnyW
5/yeYa1E0wCXAgMBAAGjYzBhMB0GA1UdDgQWBBQGmpsfU33x9aTI04Y+oXNZtPdE
ITAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFAaamx9TffH1pMjThj6hc1m0
90QhMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAqgVutt0Vyb+z
xiD2BkewhpMl0425yAA/l/VSJ4hxyXT968pk21vvHl26v9Hr7lxpuhbI87mP0zYu
QEkHDVneixCwSQXi/5E/S7fdAo74gShczNxtr18UnH1YeA32gAm56Q6XKRm4t+v4
FstVEuTGfbvE7Pi1HE4+Z7/FXxttbUcoqgRYYdZ2vyJ/0Adqp2RT8JeNnYA/u8EH
22Wv5psymsNUk8QcCMNE+3tjEUPRahphanltkE8pjkcFwRJpadbGNjHh/PqAulxP
xOu3Mqz4dWEX1xAZufHSCe96Qp1bWgvUxpVOKs7/B9dPfhgGiPEZtdmYu65xxBzn
dFlY7wyJz4sfdZMaBBSSSFCp61cpABbjNhzI+L/wM9VBD8TMPN3pM0MBkRArHtG5
Xc0yGYuPjCB31yLEQtyEFpslbei0VXF/sHyz03FJuc9SpAQ/3D2gu68zngowYI7b
nV2UqL1g52KAdoGDDIzMMEZJ4gzSqK/rYXHv5yJiqfdcZGyfFoxnNidF9Ql7v/YQ
CvGwjVRDjAS6oz/v4jXH+XTgbzRB0L9zZVcg+ZtnemZoJE6AZb0QmQZZ8mWvuMZH
u/2QeItBcy6vVR/cO5JyboTT0GFMDcx2V+IthSIVNg3rAZ3r2OvEhJn7wAzMMujj
d9qDRIueVSjAi1jTkD5OGwDxFa2DK5o=
-----END CERTIFICATE-----","00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF","Server Authentication (TLS) 1.3.6.1.5.5.7.3.1","00002172","true","false","false"
"#;

        store.add_from_ccadb_csv(bad_csv).await.unwrap();

        // Should have 0 certificates due to fingerprint mismatch
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn test_persist_to_directory() {
        let temp_dir = TempDir::new().unwrap();
        let store = RootCertificateStore::new();

        // Add certificates
        store.add_from_ccadb_csv(TEST_CCADB_CSV).await.unwrap();

        // Persist to directory
        store.persist_to_directory(temp_dir.path()).await.unwrap();

        // Check that files were created
        let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();

        // Should have 2 PEM files
        assert_eq!(entries.len(), 2);

        // All files should have .pem extension
        for entry in entries {
            let path = entry.path();
            assert_eq!(path.extension().and_then(|s| s.to_str()), Some("pem"));
        }
    }

    #[tokio::test]
    async fn test_load_from_directory() {
        let temp_dir = TempDir::new().unwrap();
        let store1 = RootCertificateStore::new();

        // Add certificates and persist
        store1.add_from_ccadb_csv(TEST_CCADB_CSV).await.unwrap();
        store1.persist_to_directory(temp_dir.path()).await.unwrap();

        // Create a new store and load from directory
        let store2 = RootCertificateStore::new();
        store2.load_from_directory(temp_dir.path()).await.unwrap();

        // Should have the same number of certificates
        assert_eq!(store2.count().await, store1.count().await);
    }

    #[tokio::test]
    async fn test_persist_additive_only() {
        let temp_dir = TempDir::new().unwrap();
        let store = RootCertificateStore::new();

        // Add certificates and persist
        store.add_from_ccadb_csv(TEST_CCADB_CSV).await.unwrap();
        store.persist_to_directory(temp_dir.path()).await.unwrap();

        let initial_files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();

        // Persist again - should not overwrite existing files
        store.persist_to_directory(temp_dir.path()).await.unwrap();

        let final_files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();

        assert_eq!(initial_files.len(), final_files.len());
    }

    #[tokio::test]
    async fn test_csv_with_colons_in_fingerprint() {
        let store = RootCertificateStore::new();

        // CSV with colons in fingerprint (common format) - using the Amazon cert which has colons
        let csv_with_colons = r#""Subject","CA Owner","X.509 Certificate (PEM)","SHA-256 Fingerprint","Intended Use Case(s) Served","CCADB Inclusion Request Case #","Apple Requested?","Google Chrome Requested?","Mozilla Requested?"
"CN=Amazon ECDSA 256 Root EU M1; O=Amazon; C=DE","Amazon Trust Services","-----BEGIN CERTIFICATE-----
MIIB6zCCAZKgAwIBAgITB8DNiWzLnBYEbBghpkxseyndPzAKBggqhkjOPQQDAjBE
MQswCQYDVQQGEwJERTEPMA0GA1UEChMGQW1hem9uMSQwIgYDVQQDExtBbWF6b24g
RUNEU0EgMjU2IFJvb3QgRVUgTTEwHhcNMjQxMTE0MTI0NTUxWhcNNDIxMTE0MTI0
NTUxWjBEMQswCQYDVQQGEwJERTEPMA0GA1UEChMGQW1hem9uMSQwIgYDVQQDExtB
bWF6b24gRUNEU0EgMjU2IFJvb3QgRVUgTTEwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARmbxff3h/YNyAeVXPAGoZhLNYsm62QAp8CTvIe4oVUWR8Yp6QvaKMG7epW
J6x3NeQeqnYYfv6xiDy9nBfRkfWXo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHQ4EFgQUcdF/ctm4GS3wEaXNtYZPbh/d5aIwHwYDVR0j
BBgwFoAUcdF/ctm4GS3wEaXNtYZPbh/d5aIwCgYIKoZIzj0EAwIDRwAwRAIgJTtJ
A4US1mx9ZUncHr8Nh6LWLI55Z8hHlbGBErijvmMCIBHZnyKPmCfaHzy751ykNFdi
g3REnz9NPIRxUcunDvcv
-----END CERTIFICATE-----","9E:AD:32:C9:28:5F:E6:8B:A2:C5:B0:FE:42:7D:14:9B:10:3F:DF:A1:D0:95:8D:77:C3:DA:0F:F2:46:E8:53:D3","Server Authentication (TLS) 1.3.6.1.5.5.7.3.1;Client Authentication 1.3.6.1.5.5.7.3.2","00002242","true","true","true"
"#;

        store.add_from_ccadb_csv(csv_with_colons).await.unwrap();

        // Should successfully parse certificate with colons in fingerprint
        assert_eq!(store.count().await, 1);
    }

    #[tokio::test]
    async fn test_empty_csv() {
        let store = RootCertificateStore::new();

        let empty_csv = r#"Subject,CA Owner,X.509 Certificate (PEM),SHA-256 Fingerprint,Intended Use Case(s) Served
"#;

        store.add_from_ccadb_csv(empty_csv).await.unwrap();

        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn test_malformed_csv() {
        let store = RootCertificateStore::new();

        // CSV with missing columns
        let malformed_csv = r#"Subject,CA Owner
"CN=Test","Test CA"
"#;

        // Should handle gracefully without panicking
        let result = store.add_from_ccadb_csv(malformed_csv).await;
        assert!(result.is_ok());
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn test_pem_with_whitespace_issues() {
        let store = RootCertificateStore::new();

        // Test with TunTrust certificate that has tabs and carriage returns added
        let csv_with_whitespace = r#""Subject","CA Owner","X.509 Certificate (PEM)","SHA-256 Fingerprint","Intended Use Case(s) Served","CCADB Inclusion Request Case #","Apple Requested?","Google Chrome Requested?","Mozilla Requested?"
"CN=TunTrust Root CA; O=Agence Nationale de Certification Electronique; C=TN","Agence Nationale de Certification Electronique","	  -----BEGIN CERTIFICATE-----
MIIFszCCA5ugAwIBAgIUEwLV4kBMkkaGFmddtLu7sms+/BMwDQYJKoZIhvcNAQEL	  
BQAwYTELMAkGA1UEBhMCVE4xNzA1BgNVBAoMLkFnZW5jZSBOYXRpb25hbGUgZGUg	  
Q2VydGlmaWNhdGlvbiBFbGVjdHJvbmlxdWUxGTAXBgNVBAMMEFR1blRydXN0IFJv	  
b3QgQ0EwHhcNMTkwNDI2MDg1NzU2WhcNNDQwNDI2MDg1NzU2WjBhMQswCQYDVQQG	  
EwJUTjE3MDUGA1UECgwuQWdlbmNlIE5hdGlvbmFsZSBkZSBDZXJ0aWZpY2F0aW9u	  
IEVsZWN0cm9uaXF1ZTEZMBcGA1UEAwwQVHVuVHJ1c3QgUm9vdCBDQTCCAiIwDQYJ	  
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMPN0/y9BFPdDCA61YguBUtB9YOCfvdZ	  
n56eY+hz2vYGqU8ftPkLHzmMmiDQfgbU7DTZhrx1W4eI8NLZ1KMKsmwb60ksPqxd	  
2JQDoOw05TDENX37Jk0bbjBU2PWARZw5rZzJJQRNmpA+TkBuimvNKWfGzC3gdOgF	  
VwpIUPp6Q9p+7FuaDmJ2/uqdHYVy7BG7NegfJ7/Boce7SBbdVtfMTqDhuazb1YMZ	  
GoXRlJfXyqNlC/M4+QKu3fZnz8k/9YosRxqZbwUN/dAdgjH8KcwAWJeRTIAAHDOF	  
li/LQcKLEITDCSSJH7UP2dl3RxiSlGBcx5kDPP73lad9UKGAwqmDrViWVSHbhlnU	  
r8a83YFuB9tgYv7sEG7aaAH0gxupPqJbI9dkxt/con3YS7qC0lH4Zr8GRuR5KiY2	  
eY8fTpkdso8MDhz/yV3A/ZAQprE38806JG60hZC/gLkMjNWb1sjxVj8agIl6qeIb	  
MlEsPvLfe/ZdeikZjuXIvTZxi11Mwh0/rViizz1wTaZQmCXcI/m4WEEIcb9PuISg	  
jwBUFfyRbVinljvrS5YnzWuioYasDXxU5mZMZl+QviGaAkYt5IPCgLnPSz7ofzwB	  
7I9ezX/SKEIBlYrilz0QIX32nRzFNKHsLA4KUiwSVXAkPcvCFDVDXSdOvsC9qnyW	  
5/yeYa1E0wCXAgMBAAGjYzBhMB0GA1UdDgQWBBQGmpsfU33x9aTI04Y+oXNZtPdE	  
ITAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFAaamx9TffH1pMjThj6hc1m0	  
90QhMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAqgVutt0Vyb+z	  
xiD2BkewhpMl0425yAA/l/VSJ4hxyXT968pk21vvHl26v9Hr7lxpuhbI87mP0zYu	  
QEkHDVneixCwSQXi/5E/S7fdAo74gShczNxtr18UnH1YeA32gAm56Q6XKRm4t+v4	  
FstVEuTGfbvE7Pi1HE4+Z7/FXxttbUcoqgRYYdZ2vyJ/0Adqp2RT8JeNnYA/u8EH	  
22Wv5psymsNUk8QcCMNE+3tjEUPRahphanltkE8pjkcFwRJpadbGNjHh/PqAulxP	  
xOu3Mqz4dWEX1xAZufHSCe96Qp1bWgvUxpVOKs7/B9dPfhgGiPEZtdmYu65xxBzn	  
dFlY7wyJz4sfdZMaBBSSSFCp61cpABbjNhzI+L/wM9VBD8TMPN3pM0MBkRArHtG5	  
Xc0yGYuPjCB31yLEQtyEFpslbei0VXF/sHyz03FJuc9SpAQ/3D2gu68zngowYI7b	  
nV2UqL1g52KAdoGDDIzMMEZJ4gzSqK/rYXHv5yJiqfdcZGyfFoxnNidF9Ql7v/YQ	  
CvGwjVRDjAS6oz/v4jXH+XTgbzRB0L9zZVcg+ZtnemZoJE6AZb0QmQZZ8mWvuMZH	  
u/2QeItBcy6vVR/cO5JyboTT0GFMDcx2V+IthSIVNg3rAZ3r2OvEhJn7wAzMMujj	  
d9qDRIueVSjAi1jTkD5OGwDxFa2DK5o=	  
  	-----END CERTIFICATE-----
","2E44102AB58CB85419451C8E19D9ACF3662CAFBC614B6A53960A30F7D0E2EB41","Server Authentication (TLS) 1.3.6.1.5.5.7.3.1;Client Authentication 1.3.6.1.5.5.7.3.2","00002172","true","false","false"
"#;

        store.add_from_ccadb_csv(csv_with_whitespace).await.unwrap();

        // Should successfully parse the certificate despite whitespace issues
        assert_eq!(store.count().await, 1);
    }
}
