use crate::oids::{CT_EKU_OID, CT_POISON_EXTENSION_OID, EXTENDED_KEY_USAGE_OID};
use crate::types::{CtError, Result};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// Extract issuer key hash from a precertificate chain without full validation.
pub fn extract_issuer_key_hash_minimal(chain: &[Vec<u8>]) -> Result<[u8; 32]> {
    if chain.is_empty() {
        return Err(CtError::BadRequest(
            "Certificate chain is empty".to_string(),
        ));
    }

    let first_cert = Certificate::from_der(&chain[0])
        .map_err(|e| CtError::BadRequest(format!("Failed to parse certificate: {}", e)))?;

    let is_precert = first_cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|exts| {
            exts.iter()
                .find(|ext| ext.extn_id == CT_POISON_EXTENSION_OID)
        })
        .is_some();

    if !is_precert {
        return Err(CtError::BadRequest(
            "Can only extract issuer key hash for precertificate chains".to_string(),
        ));
    }

    let (_has_signing_cert, real_issuer_index) = if chain.len() > 1 {
        let second_cert = Certificate::from_der(&chain[1])
            .map_err(|e| CtError::BadRequest(format!("Failed to parse certificate: {}", e)))?;

        let is_signing_cert = second_cert
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|exts| {
                exts.iter()
                    .find(|ext| ext.extn_id == EXTENDED_KEY_USAGE_OID)
            })
            .and_then(|ext| {
                let eku =
                    x509_cert::ext::pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                        .ok()?;
                Some(eku.0.iter().any(|usage| usage == &CT_EKU_OID))
            })
            .unwrap_or(false);

        if is_signing_cert {
            if chain.len() < 3 {
                return Err(CtError::BadRequest(
                    "Precertificate with signing certificate requires issuer certificate"
                        .to_string(),
                ));
            }
            (true, 2)
        } else {
            (false, 1)
        }
    } else {
        return Err(CtError::BadRequest(
            "Precertificate chain must include issuer certificate".to_string(),
        ));
    };

    if real_issuer_index >= chain.len() {
        return Err(CtError::BadRequest(
            "Missing issuer certificate in chain".to_string(),
        ));
    }

    let real_issuer = Certificate::from_der(&chain[real_issuer_index])
        .map_err(|e| CtError::BadRequest(format!("Failed to parse issuer certificate: {}", e)))?;

    let spki_der = real_issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| CtError::Internal(format!("Failed to encode SPKI: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&spki_der);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::utils::{create_precertificate_with_poison, create_test_certificate};

    #[test]
    fn test_extract_issuer_key_hash_minimal() {
        let issuer_cert = create_test_certificate();
        let precert = create_precertificate_with_poison();

        let chain = vec![precert, issuer_cert];
        let result = extract_issuer_key_hash_minimal(&chain);

        assert!(result.is_ok(), "Should be able to extract issuer key hash");
        let hash = result.unwrap();
        assert_eq!(hash.len(), 32, "Issuer key hash should be 32 bytes");
    }

    #[test]
    fn test_extract_issuer_key_hash_not_precert() {
        let cert = create_test_certificate();
        let issuer_cert = create_test_certificate();

        let chain = vec![cert, issuer_cert];
        let result = extract_issuer_key_hash_minimal(&chain);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only extract issuer key hash for precertificate"));
    }

    #[test]
    fn test_extract_issuer_key_hash_empty_chain() {
        let chain: Vec<Vec<u8>> = vec![];
        let result = extract_issuer_key_hash_minimal(&chain);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Certificate chain is empty"));
    }

    #[test]
    fn test_extract_issuer_key_hash_missing_issuer() {
        let precert = create_precertificate_with_poison();

        let chain = vec![precert];
        let result = extract_issuer_key_hash_minimal(&chain);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Precertificate chain must include issuer"));
    }
}
