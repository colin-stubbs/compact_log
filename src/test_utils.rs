#[cfg(test)]
pub mod utils {
    use crate::oids::*;
    use der::asn1::{BitString, OctetString, SetOfVec};
    use der::{Decode, Encode};
    use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
    use x509_cert::ext::{Extension, Extensions};
    use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, TbsCertificate, Version};

    pub fn create_test_public_key() -> Vec<u8> {
        use p256::ecdsa::SigningKey;
        use x509_cert::spki::EncodePublicKey;

        // Generate a deterministic test key using a fixed seed
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed.into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Export as SubjectPublicKeyInfo DER
        verifying_key.to_public_key_der().unwrap().to_vec()
    }

    pub fn create_test_certificate() -> Vec<u8> {
        create_test_certificate_with_serial(1)
    }

    pub fn create_test_certificate_with_serial(serial: u8) -> Vec<u8> {
        let cn_oid = COMMON_NAME_OID;
        let cn_value = AttributeValue::from(der::asn1::Utf8StringRef::new("Test CA").unwrap());
        let cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: cn_value,
        };
        let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![cn_attr]).unwrap());
        let name = RdnSequence::from(vec![rdn]);

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).unwrap(),
            signature: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            issuer: name.clone(),
            validity: Validity {
                not_before: Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2023, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
                not_after: Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2025, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
            },
            subject: name,
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(&create_test_public_key())
                .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        };

        cert.to_der().unwrap()
    }

    pub fn create_precertificate_with_poison() -> Vec<u8> {
        let cn_oid = COMMON_NAME_OID;
        let cn_value = AttributeValue::from(der::asn1::Utf8StringRef::new("Test Entity").unwrap());
        let cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: cn_value,
        };
        let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![cn_attr]).unwrap());
        let name = RdnSequence::from(vec![rdn]);

        let issuer_cn_value =
            AttributeValue::from(der::asn1::Utf8StringRef::new("Test CA").unwrap());
        let issuer_cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: issuer_cn_value,
        };
        let issuer_rdn =
            RelativeDistinguishedName::from(SetOfVec::try_from(vec![issuer_cn_attr]).unwrap());
        let issuer_name = RdnSequence::from(vec![issuer_rdn]);

        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(),
        };

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[2]).unwrap(),
            signature: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            issuer: issuer_name,
            validity: Validity {
                not_before: Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2024, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
                not_after: Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2025, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
            },
            subject: name,
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(&create_test_public_key())
                .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(Extensions::from(vec![poison_ext])),
        };

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        };

        cert.to_der().unwrap()
    }

    pub fn create_precertificate_with_poison_and_serial(serial: u8) -> Vec<u8> {
        let cn_oid = COMMON_NAME_OID;
        let cn_value = AttributeValue::from(der::asn1::Utf8StringRef::new("Test Entity").unwrap());
        let cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: cn_value,
        };
        let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![cn_attr]).unwrap());
        let name = RdnSequence::from(vec![rdn]);

        let issuer_cn_value =
            AttributeValue::from(der::asn1::Utf8StringRef::new("Test CA").unwrap());
        let issuer_cn_attr = AttributeTypeAndValue {
            oid: cn_oid,
            value: issuer_cn_value,
        };
        let issuer_rdn =
            RelativeDistinguishedName::from(SetOfVec::try_from(vec![issuer_cn_attr]).unwrap());
        let issuer_name = RdnSequence::from(vec![issuer_rdn]);

        let poison_ext = Extension {
            extn_id: CT_POISON_EXTENSION_OID,
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(),
        };

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).unwrap(),
            signature: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            issuer: issuer_name,
            validity: Validity {
                not_before: Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2024, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
                not_after: Time::UtcTime(
                    der::asn1::UtcTime::from_date_time(
                        der::DateTime::new(2025, 1, 1, 0, 0, 0).unwrap(),
                    )
                    .unwrap(),
                ),
            },
            subject: name,
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(&create_test_public_key())
                .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(Extensions::from(vec![poison_ext])),
        };

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        };

        cert.to_der().unwrap()
    }

    pub fn extract_test_issuer_key_hash(chain: &[Vec<u8>]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        use x509_cert::Certificate;

        // For test purposes, we use a simplified extraction that assumes
        // the issuer is always at index 1 in the chain
        assert!(chain.len() >= 2, "Chain must have at least 2 certificates");

        let issuer_cert = Certificate::from_der(&chain[1]).unwrap();
        let spki_der = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&spki_der);
        hasher.finalize().to_vec()
    }
}
