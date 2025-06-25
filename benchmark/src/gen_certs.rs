use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{ExtendedKeyUsage, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use rand::Rng;
use std::fs;
use std::io::Write;
use std::path::Path;

fn create_ca() -> Result<(PKey<openssl::pkey::Private>, X509), Box<dyn std::error::Error>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let private_key = PKey::from_ec_key(ec_key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("O", "CT Benchmark")?;
    x509_name.append_entry_by_text("CN", "Benchmark CA")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509Builder::new()?;
    cert_builder.set_version(2)?;
    let serial_number = BigNum::from_u32(rand::thread_rng().gen::<u32>())?;
    let serial = Asn1Integer::from_bn(&serial_number)?;
    cert_builder.set_serial_number(&serial)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&private_key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(30)?;
    cert_builder.set_not_after(&not_after)?;

    // Add Basic Constraints extension - CRITICAL for CA certificates
    use openssl::x509::extension::BasicConstraints;
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    cert_builder.append_extension(basic_constraints)?;

    use openssl::x509::extension::KeyUsage;
    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()?;
    cert_builder.append_extension(key_usage)?;

    cert_builder.sign(&private_key, MessageDigest::sha256())?;

    let certificate = cert_builder.build();

    Ok((private_key, certificate))
}

fn generate_certificate(
    ca_key: &PKey<openssl::pkey::Private>,
    ca_cert: &X509,
    index: u64,
) -> Result<X509, Box<dyn std::error::Error>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("O", "CT Benchmark")?;
    x509_name.append_entry_by_text("CN", &format!("bench-{}.example.com", index))?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509Builder::new()?;
    cert_builder.set_version(2)?;
    let serial_number = BigNum::from_u32(rand::thread_rng().gen::<u32>())?;
    let serial = Asn1Integer::from_bn(&serial_number)?;
    cert_builder.set_serial_number(&serial)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(ca_cert.issuer_name())?;
    cert_builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(90)?;
    cert_builder.set_not_after(&not_after)?;

    let eku = ExtendedKeyUsage::new().server_auth().build()?;
    cert_builder.append_extension(eku)?;

    let san = SubjectAlternativeName::new()
        .dns(&format!("bench-{}.example.com", index))
        .build(&cert_builder.x509v3_context(Some(&ca_cert), None))?;
    cert_builder.append_extension(san)?;

    cert_builder.sign(&ca_key, MessageDigest::sha256())?;

    Ok(cert_builder.build())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!(
            "Usage: {} <number_of_certificates> <output_directory>",
            args[0]
        );
        std::process::exit(1);
    }

    let num_certs: u64 = args[1].parse()?;
    let output_dir = &args[2];
    let num_threads = 10;

    fs::create_dir_all(output_dir)?;

    println!("Creating CA certificate...");
    let (ca_key, ca_cert) = create_ca()?;
    let ca_cert_path = Path::new(output_dir).join("ca.crt");
    let ca_key_path = Path::new(output_dir).join("ca.key");
    let ca_pem_path = Path::new(output_dir).join("ca.pem");

    fs::write(&ca_cert_path, ca_cert.to_pem()?)?;
    fs::write(&ca_key_path, ca_key.private_key_to_pem_pkcs8()?)?;
    fs::write(&ca_pem_path, ca_cert.to_pem()?)?;

    println!("CA certificate saved to: {:?}", ca_cert_path);
    println!("CA key saved to: {:?}", ca_key_path);
    println!("CA PEM saved to: {:?}", ca_pem_path);

    println!(
        "Generating {} certificates split across {} thread files",
        num_certs, num_threads
    );

    let certs_per_thread = num_certs / num_threads as u64;
    let remainder = num_certs % num_threads as u64;

    let mut cert_index = 0u64;

    for thread_id in 0..num_threads {
        let thread_certs = if thread_id < remainder as usize {
            certs_per_thread + 1
        } else {
            certs_per_thread
        };

        let pem_path = Path::new(output_dir).join(format!("leafs_thread_{}.pem", thread_id));
        let mut pem_file = fs::File::create(&pem_path)?;

        println!(
            "Generating {} certificates for thread {}...",
            thread_certs, thread_id
        );

        for i in 0..thread_certs {
            if i % 1000 == 0 && i > 0 {
                println!(
                    "Thread {}: Generated {}/{} certificates...",
                    thread_id, i, thread_certs
                );
            }

            let cert = generate_certificate(&ca_key, &ca_cert, cert_index)?;
            let cert_pem = cert.to_pem()?;

            pem_file.write_all(&cert_pem)?;

            cert_index += 1;
        }

        println!(
            "Thread {}: Generated {} leaf certificates",
            thread_id, thread_certs
        );
        println!("Leaf certificates saved to: {:?}", pem_path);
    }

    println!(
        "Total: Generated {} leaf certificates across {} files",
        cert_index, num_threads
    );
    println!("CA certificate stored separately for shared access");

    Ok(())
}
