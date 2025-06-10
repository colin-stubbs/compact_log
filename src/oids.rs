//! Object Identifier (OID) constants used throughout the codebase

use der::asn1::ObjectIdentifier;

pub const CT_POISON_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.3");
pub const CT_EKU_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.4");

pub const AUTHORITY_KEY_IDENTIFIER_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");

pub const SUBJECT_KEY_IDENTIFIER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

pub const BASIC_CONSTRAINTS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

pub const EXTENDED_KEY_USAGE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

pub const ECDSA_WITH_SHA256_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

pub const ECDSA_WITH_SHA384_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

pub const ECDSA_WITH_SHA512_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

pub const SHA256_WITH_RSA_ENCRYPTION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

pub const SHA384_WITH_RSA_ENCRYPTION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");

pub const SHA512_WITH_RSA_ENCRYPTION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

pub const SHA1_WITH_RSA_ENCRYPTION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");

pub const ASN1_NULL: &[u8] = &[0x05, 0x00];

#[cfg(test)]
pub const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

#[cfg(test)]
pub const BASIC_CONSTRAINTS_CA_TRUE: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xFF];

#[cfg(test)]
pub const EKU_CT_ENCODED: &[u8] = &[
    0x30, 0x0C, // SEQUENCE of 12 bytes
    0x06, 0x0A, // OID of 10 bytes
    0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x04, // 1.3.6.1.4.1.11129.2.4.4
];
