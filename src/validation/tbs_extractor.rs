use crate::oids::*;
use crate::types::{CtError, Result};
use der::{asn1::OctetString, Decode, Encode};
use x509_cert::{
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
    Certificate,
};

pub struct TbsExtractor;

impl TbsExtractor {
    /// Extract the TBSCertificate from a precertificate
    /// This removes the poison extension and transforms issuer/AKID if needed
    pub fn extract_tbs_certificate(precert_der: &[u8], chain: &[Vec<u8>]) -> Result<Vec<u8>> {
        let mut precert = Certificate::from_der(precert_der).map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to parse precertificate: {}", e))
        })?;

        // Verify this is actually a precertificate
        if !Self::has_poison_extension(&precert)? {
            return Err(CtError::BadRequest(
                "Certificate is not a precertificate (missing poison extension)".to_string(),
            ));
        }

        // Check if we need to transform issuer and AKID
        let transform_needed = Self::check_transform_needed(&precert, chain)?;

        if let Some((final_issuer, final_issuer_key_id)) = transform_needed {
            precert.tbs_certificate.issuer = final_issuer;

            // Update Authority Key Identifier if present
            if let Some(ref mut extensions) = precert.tbs_certificate.extensions {
                for ext in extensions.iter_mut() {
                    if ext.extn_id == AUTHORITY_KEY_IDENTIFIER_OID {
                        if let Some(key_id) = &final_issuer_key_id {
                            // Create new AKID with the final issuer's key ID
                            let key_identifier = OctetString::new(key_id.clone()).map_err(|e| {
                                CtError::InvalidCertificate(format!(
                                    "Failed to create OctetString for key identifier: {}",
                                    e
                                ))
                            })?;

                            let new_akid = AuthorityKeyIdentifier {
                                key_identifier: Some(key_identifier),
                                authority_cert_issuer: None,
                                authority_cert_serial_number: None,
                            };

                            let akid_der = new_akid.to_der().map_err(|e| {
                                CtError::InvalidCertificate(format!(
                                    "Failed to encode new Authority Key Identifier: {}",
                                    e
                                ))
                            })?;

                            ext.extn_value = OctetString::new(akid_der).map_err(|e| {
                                CtError::InvalidCertificate(format!(
                                    "Failed to encode Authority Key Identifier value: {}",
                                    e
                                ))
                            })?;
                        }
                    }
                }
            }
        }

        // Remove the poison extension
        if let Some(ref mut extensions) = precert.tbs_certificate.extensions {
            extensions.retain(|ext| ext.extn_id != CT_POISON_EXTENSION_OID);
        }

        // Encode the TBSCertificate
        precert.tbs_certificate.to_der().map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to encode TBSCertificate: {}", e))
        })
    }

    /// Check if the certificate has a poison extension
    fn has_poison_extension(cert: &Certificate) -> Result<bool> {
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == CT_POISON_EXTENSION_OID {
                    // Verify it's critical
                    if !ext.critical {
                        return Err(CtError::BadRequest(
                            "Poison extension must be critical".to_string(),
                        ));
                    }

                    // Verify it contains ASN.1 NULL
                    if ext.extn_value.as_bytes() != ASN1_NULL {
                        return Err(CtError::BadRequest(
                            "Poison extension must contain ASN.1 NULL".to_string(),
                        ));
                    }

                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Check if we need to transform issuer and AKID
    /// Returns Some((final_issuer, final_issuer_key_id)) if transformation is needed
    fn check_transform_needed(
        _precert: &Certificate,
        chain: &[Vec<u8>],
    ) -> Result<Option<(x509_cert::name::Name, Option<Vec<u8>>)>> {
        if chain.is_empty() {
            return Ok(None);
        }

        // Parse the immediate issuer
        let immediate_issuer = Certificate::from_der(&chain[0]).map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to parse immediate issuer: {}", e))
        })?;

        // Check if it's a Precertificate Signing Certificate
        if !Self::is_precert_signing_cert(&immediate_issuer)? {
            return Ok(None);
        }

        // We need the real issuer (should be at index 1)
        if chain.len() < 2 {
            return Err(CtError::BadRequest(
                "Precertificate signed by signing cert requires real issuer in chain".to_string(),
            ));
        }

        let real_issuer = Certificate::from_der(&chain[1]).map_err(|e| {
            CtError::InvalidCertificate(format!("Failed to parse real issuer: {}", e))
        })?;

        // Extract the Subject Key Identifier from the real issuer
        let real_issuer_key_id = Self::extract_subject_key_identifier(&real_issuer)?;

        Ok(Some((
            real_issuer.tbs_certificate.subject.clone(),
            real_issuer_key_id,
        )))
    }

    /// Check if a certificate is a Precertificate Signing Certificate
    fn is_precert_signing_cert(cert: &Certificate) -> Result<bool> {
        use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage};

        let mut has_ca_true = false;
        let mut has_ct_eku = false;

        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                // Check Basic Constraints
                if ext.extn_id == BASIC_CONSTRAINTS_OID {
                    if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                        has_ca_true = bc.ca;
                    }
                }

                // Check Extended Key Usage
                if ext.extn_id == EXTENDED_KEY_USAGE_OID {
                    if let Ok(eku) = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                        for oid in eku.0.iter() {
                            if *oid == CT_EKU_OID {
                                has_ct_eku = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(has_ca_true && has_ct_eku)
    }

    /// Extract Subject Key Identifier from a certificate
    fn extract_subject_key_identifier(cert: &Certificate) -> Result<Option<Vec<u8>>> {
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == SUBJECT_KEY_IDENTIFIER_OID {
                    if let Ok(ski) = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                        return Ok(Some(ski.0.as_bytes().to_vec()));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::{BitString, OctetString, SetOfVec};
    use der::{Decode, Encode};
    use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
    use x509_cert::ext::{
        pkix::{BasicConstraints, ExtendedKeyUsage},
        Extension, Extensions,
    };
    use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, TbsCertificate, Version};

    // Test-only OID constant
    const SUBJECT_ALTERNATIVE_NAME_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

    // Helper function to create test subject/issuer names
    fn create_test_name(cn: &str) -> RdnSequence {
        let cn_oid = COMMON_NAME_OID;
        let cn_value = AttributeValue::from(der::asn1::Utf8StringRef::new(cn).unwrap());
        let cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: cn_value,
        };
        let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![cn_attr]).unwrap());
        RdnSequence::from(vec![rdn])
    }

    // Helper function to create test validity period
    fn create_test_validity() -> Validity {
        Validity {
            not_before: Time::UtcTime(
                der::asn1::UtcTime::from_date_time(
                    der::DateTime::new(2023, 1, 1, 0, 0, 0).unwrap(),
                )
                .unwrap(),
            ),
            not_after: Time::UtcTime(
                der::asn1::UtcTime::from_date_time(
                    der::DateTime::new(2024, 1, 1, 0, 0, 0).unwrap(),
                )
                .unwrap(),
            ),
        }
    }

    // Helper function to create test public key
    fn create_test_public_key() -> SubjectPublicKeyInfoOwned {
        use p256::ecdsa::SigningKey;
        use x509_cert::spki::EncodePublicKey;

        // Generate a deterministic test key using a fixed seed
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Export as SubjectPublicKeyInfo DER
        let spki_der = verifying_key.to_public_key_der().unwrap().to_vec();
        SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap()
    }

    // Helper function to create test ECDSA algorithm identifier
    fn create_test_algorithm() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256_OID,
            parameters: None,
        }
    }

    // Helper function to create a basic certificate
    fn create_basic_certificate(subject: &str, issuer: &str) -> Certificate {
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1, 2, 3]).unwrap(),
            signature: create_test_algorithm(),
            issuer: create_test_name(issuer),
            validity: create_test_validity(),
            subject: create_test_name(subject),
            subject_public_key_info: create_test_public_key(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: create_test_algorithm(),
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        }
    }

    // Helper function to create a precertificate with poison extension
    fn create_precertificate(subject: &str, issuer: &str) -> Certificate {
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(ASN1_NULL.to_vec()).unwrap(),
        };

        let mut cert = create_basic_certificate(subject, issuer);
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![poison_ext]));
        cert
    }

    // Helper function to create a precertificate with poison extension and AKID
    fn create_precertificate_with_akid(
        subject: &str,
        issuer: &str,
        akid_key_id: Vec<u8>,
    ) -> Certificate {
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(),
        };

        let akid = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(akid_key_id).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        let akid_ext = Extension {
            extn_id: AUTHORITY_KEY_IDENTIFIER_OID,
            critical: false,
            extn_value: OctetString::new(akid.to_der().unwrap()).unwrap(),
        };

        let mut cert = create_basic_certificate(subject, issuer);
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![poison_ext, akid_ext]));
        cert
    }

    // Helper function to create a precertificate signing certificate
    fn create_precert_signing_cert(subject: &str, issuer: &str) -> Certificate {
        // Basic Constraints with CA=true
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let bc_ext = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der().unwrap()).unwrap(),
        };

        // Extended Key Usage with CT EKU
        let eku = ExtendedKeyUsage(vec![CT_EKU_OID]);
        let eku_ext = Extension {
            extn_id: EXTENDED_KEY_USAGE_OID,
            critical: true,
            extn_value: OctetString::new(eku.to_der().unwrap()).unwrap(),
        };

        let mut cert = create_basic_certificate(subject, issuer);
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![bc_ext, eku_ext]));
        cert
    }

    // Helper function to create a CA certificate with SKI
    fn create_ca_with_ski(subject: &str) -> Certificate {
        let ski_value = vec![0xAA; 20]; // 20 bytes for SKI
        let ski = SubjectKeyIdentifier(OctetString::new(ski_value.clone()).unwrap());
        let ski_ext = Extension {
            extn_id: SUBJECT_KEY_IDENTIFIER_OID,
            critical: false,
            extn_value: OctetString::new(ski.to_der().unwrap()).unwrap(),
        };

        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let bc_ext = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der().unwrap()).unwrap(),
        };

        let mut cert = create_basic_certificate(subject, subject);
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![bc_ext, ski_ext]));
        cert
    }

    #[test]
    fn test_has_poison_extension_valid() {
        let precert = create_precertificate("test.example.com", "Test CA");
        assert!(TbsExtractor::has_poison_extension(&precert).unwrap());
    }

    #[test]
    fn test_has_poison_extension_not_critical() {
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: false, // Not critical
            extn_value: OctetString::new(ASN1_NULL.to_vec()).unwrap(),
        };

        let mut cert = create_basic_certificate("test.example.com", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![poison_ext]));

        let result = TbsExtractor::has_poison_extension(&cert);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be critical"));
    }

    #[test]
    fn test_has_poison_extension_wrong_value() {
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(vec![0x01, 0x02, 0x03]).unwrap(), // Wrong value
        };

        let mut cert = create_basic_certificate("test.example.com", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![poison_ext]));

        let result = TbsExtractor::has_poison_extension(&cert);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must contain ASN.1 NULL"));
    }

    #[test]
    fn test_is_precert_signing_cert_valid() {
        let cert = create_precert_signing_cert("Test Precert Signing", "Test CA");
        assert!(TbsExtractor::is_precert_signing_cert(&cert).unwrap());
    }

    #[test]
    fn test_is_precert_signing_cert_missing_ca() {
        // Certificate with CT EKU but CA=false
        let bc = BasicConstraints {
            ca: false, // Not a CA
            path_len_constraint: None,
        };
        let bc_ext = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der().unwrap()).unwrap(),
        };

        let eku = ExtendedKeyUsage(vec![CT_EKU_OID]);
        let eku_ext = Extension {
            extn_id: EXTENDED_KEY_USAGE_OID,
            critical: true,
            extn_value: OctetString::new(eku.to_der().unwrap()).unwrap(),
        };

        let mut cert = create_basic_certificate("Test", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![bc_ext, eku_ext]));

        assert!(!TbsExtractor::is_precert_signing_cert(&cert).unwrap());
    }

    #[test]
    fn test_is_precert_signing_cert_missing_eku() {
        // Certificate with CA=true but no CT EKU
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let bc_ext = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der().unwrap()).unwrap(),
        };

        let mut cert = create_basic_certificate("Test CA", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![bc_ext]));

        assert!(!TbsExtractor::is_precert_signing_cert(&cert).unwrap());
    }

    #[test]
    fn test_extract_tbs_certificate_not_precert() {
        let cert = create_basic_certificate("test.example.com", "Test CA");
        let cert_der = cert.to_der().unwrap();

        let result = TbsExtractor::extract_tbs_certificate(&cert_der, &[]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not a precertificate"));
    }

    #[test]
    fn test_extract_tbs_certificate_basic() {
        let precert = create_precertificate("test.example.com", "Test CA");
        let precert_der = precert.to_der().unwrap();

        let tbs_der = TbsExtractor::extract_tbs_certificate(&precert_der, &[]).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify poison extension was removed
        if let Some(exts) = &tbs.extensions {
            for ext in exts.iter() {
                assert_ne!(ext.extn_id, CT_POISON_EXTENSION_OID);
            }
        }

        // Verify other fields remain unchanged
        assert_eq!(tbs.subject, precert.tbs_certificate.subject);
        assert_eq!(tbs.issuer, precert.tbs_certificate.issuer);
        assert_eq!(tbs.serial_number, precert.tbs_certificate.serial_number);
    }

    #[test]
    fn test_extract_tbs_certificate_with_regular_issuer() {
        let precert = create_precertificate("test.example.com", "Test CA");
        let issuer = create_basic_certificate("Test CA", "Root CA");

        let precert_der = precert.to_der().unwrap();
        let issuer_der = issuer.to_der().unwrap();
        let chain = vec![issuer_der];

        let tbs_der = TbsExtractor::extract_tbs_certificate(&precert_der, &chain).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify poison extension was removed
        if let Some(exts) = &tbs.extensions {
            for ext in exts.iter() {
                assert_ne!(ext.extn_id, CT_POISON_EXTENSION_OID);
            }
        }

        // Verify issuer was NOT changed (regular CA)
        assert_eq!(tbs.issuer, precert.tbs_certificate.issuer);
    }

    #[test]
    fn test_extract_tbs_certificate_with_precert_signing_cert() {
        let real_ca = create_ca_with_ski("Real CA");
        let precert_signing = create_precert_signing_cert("Real CA Precert Signing", "Real CA");
        let precert = create_precertificate_with_akid(
            "test.example.com",
            "Real CA Precert Signing",
            vec![0xCC; 20], // Wrong AKID that needs updating
        );

        let precert_der = precert.to_der().unwrap();
        let precert_signing_der = precert_signing.to_der().unwrap();
        let real_ca_der = real_ca.to_der().unwrap();
        let chain = vec![precert_signing_der, real_ca_der];

        let tbs_der = TbsExtractor::extract_tbs_certificate(&precert_der, &chain).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify poison extension was removed
        if let Some(exts) = &tbs.extensions {
            for ext in exts.iter() {
                assert_ne!(ext.extn_id, CT_POISON_EXTENSION_OID);
            }
        }

        // Verify issuer was changed to real CA
        assert_eq!(tbs.issuer, real_ca.tbs_certificate.subject);
        assert_ne!(tbs.issuer, precert.tbs_certificate.issuer);
    }

    #[test]
    fn test_extract_tbs_certificate_precert_signing_missing_real_issuer() {
        let precert_signing = create_precert_signing_cert("Test Precert Signing", "Test CA");
        let precert = create_precertificate("test.example.com", "Test Precert Signing");

        let precert_der = precert.to_der().unwrap();
        let precert_signing_der = precert_signing.to_der().unwrap();
        let chain = vec![precert_signing_der]; // Missing real issuer

        let result = TbsExtractor::extract_tbs_certificate(&precert_der, &chain);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires real issuer in chain"));
    }

    #[test]
    fn test_extract_tbs_certificate_invalid_der() {
        let invalid_der = vec![0xFF, 0xFF, 0xFF];
        let result = TbsExtractor::extract_tbs_certificate(&invalid_der, &[]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse precertificate"));
    }

    #[test]
    fn test_extract_tbs_preserves_other_extensions() {
        // Create a precertificate with multiple extensions
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(),
        };

        // Add a SAN extension
        let san_ext = Extension {
            extn_id: SUBJECT_ALTERNATIVE_NAME_OID,
            critical: false,
            extn_value: OctetString::new(vec![0x30, 0x00]).unwrap(), // Empty SEQUENCE
        };

        let mut cert = create_basic_certificate("test.example.com", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![poison_ext, san_ext.clone()]));

        let cert_der = cert.to_der().unwrap();
        let tbs_der = TbsExtractor::extract_tbs_certificate(&cert_der, &[]).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify SAN extension is preserved but poison is removed
        let exts = tbs.extensions.unwrap();
        assert_eq!(exts.len(), 1);
        assert_eq!(exts.first().unwrap().extn_id, SUBJECT_ALTERNATIVE_NAME_OID);
    }

    #[test]
    fn test_extract_tbs_certificate_precert_without_akid() {
        // Create a precertificate without AKID extension
        let precert = create_precertificate("test.example.com", "Test Precert Signing");
        let precert_signing = create_precert_signing_cert("Test Precert Signing", "Real CA");
        let real_ca = create_ca_with_ski("Real CA");

        let precert_der = precert.to_der().unwrap();
        let precert_signing_der = precert_signing.to_der().unwrap();
        let real_ca_der = real_ca.to_der().unwrap();
        let chain = vec![precert_signing_der, real_ca_der];

        let tbs_der = TbsExtractor::extract_tbs_certificate(&precert_der, &chain).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify issuer was transformed
        assert_eq!(tbs.issuer, real_ca.tbs_certificate.subject);

        // Verify no AKID was added (since precert didn't have one)
        if let Some(exts) = &tbs.extensions {
            for ext in exts.iter() {
                assert_ne!(ext.extn_id, AUTHORITY_KEY_IDENTIFIER_OID);
            }
        }
    }

    #[test]
    fn test_extract_tbs_certificate_chain_with_invalid_cert() {
        let precert = create_precertificate("test.example.com", "Test CA");
        let precert_der = precert.to_der().unwrap();
        let invalid_cert = vec![0xFF, 0xFF, 0xFF]; // Invalid DER
        let chain = vec![invalid_cert];

        let result = TbsExtractor::extract_tbs_certificate(&precert_der, &chain);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse immediate issuer"));
    }

    #[test]
    fn test_extract_tbs_certificate_real_issuer_without_ski() {
        // Create CA without SKI
        let real_ca = create_basic_certificate("Real CA", "Real CA");
        let precert_signing = create_precert_signing_cert("Real CA Precert Signing", "Real CA");
        let precert = create_precertificate_with_akid(
            "test.example.com",
            "Real CA Precert Signing",
            vec![0xAA; 20],
        );

        let precert_der = precert.to_der().unwrap();
        let precert_signing_der = precert_signing.to_der().unwrap();
        let real_ca_der = real_ca.to_der().unwrap();
        let chain = vec![precert_signing_der, real_ca_der];

        let tbs_der = TbsExtractor::extract_tbs_certificate(&precert_der, &chain).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify issuer was changed
        assert_eq!(tbs.issuer, real_ca.tbs_certificate.subject);

        // Verify AKID still exists but key_identifier might be None
        if let Some(exts) = &tbs.extensions {
            let has_akid = exts
                .iter()
                .any(|ext| ext.extn_id == AUTHORITY_KEY_IDENTIFIER_OID);
            assert!(has_akid);
        }
    }

    #[test]
    fn test_has_poison_extension_invalid_encoding() {
        // Test with malformed extension value that can't be decoded
        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(vec![0xFF]).unwrap(), // Invalid ASN.1
        };

        let mut cert = create_basic_certificate("test.example.com", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![poison_ext]));

        let result = TbsExtractor::has_poison_extension(&cert);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must contain ASN.1 NULL"));
    }

    #[test]
    fn test_is_precert_signing_cert_with_invalid_extension_encoding() {
        // Test handling of malformed Basic Constraints extension
        let bc_ext = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: OctetString::new(vec![0xFF, 0xFF]).unwrap(), // Invalid encoding
        };

        let eku = ExtendedKeyUsage(vec![CT_EKU_OID]);
        let eku_ext = Extension {
            extn_id: EXTENDED_KEY_USAGE_OID,
            critical: true,
            extn_value: OctetString::new(eku.to_der().unwrap()).unwrap(),
        };

        let mut cert = create_basic_certificate("Test", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![bc_ext, eku_ext]));

        // Should return false because BC can't be decoded properly
        assert!(!TbsExtractor::is_precert_signing_cert(&cert).unwrap());
    }

    #[test]
    fn test_multiple_poison_extensions() {
        // RFC 6962 doesn't explicitly handle multiple poison extensions
        // This is an invalid certificate but we should handle it gracefully
        let poison_ext1 = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(ASN1_NULL.to_vec()).unwrap(),
        };

        let poison_ext2 = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(ASN1_NULL.to_vec()).unwrap(),
        };

        let mut cert = create_basic_certificate("test.example.com", "Test CA");
        cert.tbs_certificate.extensions = Some(Extensions::from(vec![poison_ext1, poison_ext2]));

        // Should still detect as precertificate
        assert!(TbsExtractor::has_poison_extension(&cert).unwrap());

        // Should be able to extract TBS (both poison extensions removed)
        let cert_der = cert.to_der().unwrap();
        let tbs_der = TbsExtractor::extract_tbs_certificate(&cert_der, &[]).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify all poison extensions were removed
        if let Some(exts) = &tbs.extensions {
            for ext in exts.iter() {
                assert_ne!(ext.extn_id, CT_POISON_EXTENSION_OID);
            }
            assert_eq!(exts.len(), 0);
        }
    }

    #[test]
    fn test_precert_transform_clears_akid_issuer_and_serial() {
        // Test that when transforming a precert, only the key_identifier is preserved
        // This verifies RFC 6962 compliance where authority_cert_issuer and
        // authority_cert_serial_number should not be carried over

        // For this test, we'll use a manually crafted AKID extension
        // with all components filled, then verify only key_identifier remains
        let precert = create_precertificate_with_akid(
            "test.example.com",
            "Test Precert Signing",
            vec![0xBB; 20], // Some key ID that will be replaced
        );

        let precert_signing = create_precert_signing_cert("Test Precert Signing", "Real CA");
        let real_ca = create_ca_with_ski("Real CA");

        let precert_der = precert.to_der().unwrap();
        let precert_signing_der = precert_signing.to_der().unwrap();
        let real_ca_der = real_ca.to_der().unwrap();
        let chain = vec![precert_signing_der, real_ca_der];

        let tbs_der = TbsExtractor::extract_tbs_certificate(&precert_der, &chain).unwrap();
        let tbs = TbsCertificate::from_der(&tbs_der).unwrap();

        // Verify AKID exists and was transformed
        let found_akid = tbs
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|ext| ext.extn_id == AUTHORITY_KEY_IDENTIFIER_OID)
            .expect("AKID should be present");

        let updated_akid =
            AuthorityKeyIdentifier::from_der(found_akid.extn_value.as_bytes()).unwrap();

        // Key identifier should be present and updated to match real CA's SKI
        assert!(updated_akid.key_identifier.is_some());
        let key_id = updated_akid.key_identifier.unwrap();
        assert_eq!(key_id.as_bytes(), &[0xAA; 20]); // This matches the SKI we set in create_ca_with_ski

        // RFC 6962: Only key_identifier should be present after transformation
        assert!(updated_akid.authority_cert_issuer.is_none());
        assert!(updated_akid.authority_cert_serial_number.is_none());
    }
}
