//! Certificates netNIMA makes: its own, for TLS servers with none chosen,
//! and sets of a CA with a server's and a client's certificate it signed,
//! for devices to test with.
//!
//! Every key is ECDSA P-256, which small TLS stacks such as mbedTLS and
//! wolfSSL all take.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::{Datelike, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;

use crate::net::tls::fingerprint;

/// The names a certificate made for this computer is for: localhost and
/// every address it has.
pub fn local_names() -> Vec<String> {
    let mut names = vec!["localhost".to_string()];
    let mut addresses: BTreeSet<String> = BTreeSet::new();
    addresses.insert("127.0.0.1".into());
    addresses.insert("::1".into());
    for ip in crate::net::own_addresses() {
        // Link-local IPv6 addresses need a zone, which a certificate cannot hold.
        if let std::net::IpAddr::V6(v6) = ip
            && v6.segments()[0] & 0xffc0 == 0xfe80
        {
            continue;
        }
        addresses.insert(ip.to_string());
    }
    names.extend(addresses);
    names
}

/// Where netNIMA keeps its own certificate, so it stays the same from one
/// run to the next and a device can be told to trust it. Unset, it is made
/// again each run.
static OWN_FOLDER: Mutex<Option<PathBuf>> = Mutex::new(None);

/// The folder to keep netNIMA's own certificate in.
pub fn keep_own_in(folder: &Path) {
    if let Ok(mut kept) = OWN_FOLDER.lock() {
        *kept = Some(folder.to_path_buf());
    }
}

/// The files netNIMA's own certificate and key are kept in, made now if
/// they are not there yet.
pub fn own_files() -> Result<(PathBuf, PathBuf), String> {
    let folder = OWN_FOLDER
        .lock()
        .ok()
        .and_then(|kept| kept.clone())
        .ok_or("netNIMA has no folder to keep its certificate in.")?;
    let cert = folder.join("netnima-server.crt");
    let key = folder.join("netnima-server.key");
    if !(cert.exists() && key.exists()) {
        let made = self_signed(&local_names())?;
        std::fs::create_dir_all(&folder)
            .map_err(|error| format!("Could not make {}: {error}", folder.display()))?;
        write(&cert, made.cert_pem.as_bytes())?;
        write(&key, made.key_pem.as_bytes())?;
    }
    Ok((cert, key))
}

/// netNIMA's own server certificate and key: the one kept, or one made for
/// this run when none can be kept. It is self-signed, so a client must be
/// told to trust it, or not to check.
pub(crate) fn own() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    if let Ok((cert, key)) = own_files()
        && let (Ok(cert), Ok(key)) = (std::fs::read(&cert), std::fs::read(&key))
        && let Ok(chain) = CertificateDer::pem_slice_iter(&cert)
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        && let Ok(key) = PrivateKeyDer::from_pem_slice(&key)
        && !chain.is_empty()
    {
        return Ok((chain, key));
    }
    /// A certificate's and its key's DER bytes, or why they could not be made.
    type Made = Result<(Vec<u8>, Vec<u8>), String>;
    static MADE: OnceLock<Made> = OnceLock::new();
    let (cert, key) = MADE
        .get_or_init(|| self_signed(&local_names()).map(|made| (made.cert_der, made.key_der)))
        .clone()?;
    Ok((
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
    ))
}

/// A self-signed certificate and its PKCS#8 key, DER both, made now for a
/// client that must show one and was given none.
pub(crate) fn throwaway() -> Result<(Vec<u8>, Vec<u8>), String> {
    self_signed(&["netnima-client".to_string()]).map(|made| (made.cert_der, made.key_der))
}

/// A certificate and its key, made here.
struct Made {
    cert_pem: String,
    cert_der: Vec<u8>,
    key_pem: String,
    key_der: Vec<u8>,
}

fn rcgen_problem(error: rcgen::Error) -> String {
    format!("The certificate could not be made: {error}")
}

/// A self-signed certificate for `names`, valid for ten years from yesterday.
fn self_signed(names: &[String]) -> Result<Made, String> {
    let mut params = CertificateParams::new(names.to_vec()).map_err(rcgen_problem)?;
    params
        .distinguished_name
        .push(DnType::CommonName, "netNIMA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "netNIMA");
    set_validity(&mut params, 10);
    let key = KeyPair::generate().map_err(rcgen_problem)?;
    let cert = params.self_signed(&key).map_err(rcgen_problem)?;
    Ok(Made {
        cert_pem: cert.pem(),
        cert_der: cert.der().to_vec(),
        key_pem: key.serialize_pem(),
        key_der: key.serialize_der(),
    })
}

/// Valid from yesterday, so a clock a little behind still takes it, for `years`.
fn set_validity(params: &mut CertificateParams, years: u32) {
    let from = Utc::now() - Duration::days(1);
    let years = years.clamp(1, 100) as i32;
    params.not_before = rcgen::date_time_ymd(from.year(), from.month() as u8, from.day() as u8);
    // The 29th of February does not come every year.
    let day = from.day().min(28) as u8;
    params.not_after = rcgen::date_time_ymd(from.year() + years, from.month() as u8, day);
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes)
        .map_err(|error| format!("Could not write {}: {error}", path.display()))
}

/// What `make_set` asks for.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(default)]
pub struct SetRequest {
    /// The folder the files go to.
    pub folder: String,
    /// The names and addresses the server's certificate is for.
    pub server_names: Vec<String>,
    /// The name in the client's certificate, such as a device's serial number.
    pub client_name: String,
    /// How many years they are valid for.
    pub years: u32,
}

impl Default for SetRequest {
    fn default() -> Self {
        Self {
            folder: String::new(),
            server_names: local_names(),
            client_name: "device".into(),
            years: 10,
        }
    }
}

/// What `make_set` made.
#[derive(Clone, Debug, Serialize)]
pub struct MadeSet {
    /// Every file written, in the order written.
    pub files: Vec<String>,
    pub ca_sha256: String,
    pub server_sha256: String,
    pub client_sha256: String,
}

/// Makes a CA, and a server's and a client's certificate it signed, and
/// writes them to the folder: PEM files for netNIMA and most stacks, DER
/// files, and `certs.h` with all of them as C arrays for firmware.
pub fn make_set(request: &SetRequest) -> Result<MadeSet, String> {
    let folder = PathBuf::from(request.folder.trim());
    if request.folder.trim().is_empty() {
        return Err("Choose the folder the certificates go to.".into());
    }
    let server_names: Vec<String> = request
        .server_names
        .iter()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();
    if server_names.is_empty() {
        return Err("Enter a name or an address for the server's certificate.".into());
    }
    let client_name = match request.client_name.trim() {
        "" => "device",
        name => name,
    };

    let mut ca = CertificateParams::new(Vec::new()).map_err(rcgen_problem)?;
    ca.distinguished_name
        .push(DnType::CommonName, "netNIMA test CA");
    ca.distinguished_name
        .push(DnType::OrganizationName, "netNIMA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut ca, request.years);
    let ca_key = KeyPair::generate().map_err(rcgen_problem)?;
    let ca_cert = ca.self_signed(&ca_key).map_err(rcgen_problem)?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca_key_der = ca_key.serialize_der();
    let issuer = Issuer::new(ca, ca_key);

    let mut server = CertificateParams::new(server_names.clone()).map_err(rcgen_problem)?;
    server
        .distinguished_name
        .push(DnType::CommonName, server_names[0].clone());
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server.use_authority_key_identifier_extension = true;
    set_validity(&mut server, request.years);
    let server_key = KeyPair::generate().map_err(rcgen_problem)?;
    let server_cert = server
        .signed_by(&server_key, &issuer)
        .map_err(rcgen_problem)?;

    let mut client = CertificateParams::new(Vec::new()).map_err(rcgen_problem)?;
    client
        .distinguished_name
        .push(DnType::CommonName, client_name);
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client.use_authority_key_identifier_extension = true;
    set_validity(&mut client, request.years);
    let client_key = KeyPair::generate().map_err(rcgen_problem)?;
    let client_cert = client
        .signed_by(&client_key, &issuer)
        .map_err(rcgen_problem)?;

    std::fs::create_dir_all(&folder)
        .map_err(|error| format!("Could not make {}: {error}", folder.display()))?;
    let ca_pem = ca_cert.pem();
    let server_pem = server_cert.pem();
    let client_pem = client_cert.pem();
    let server_key_pem = server_key.serialize_pem();
    let client_key_pem = client_key.serialize_pem();
    let server_key_der = server_key.serialize_der();
    let client_key_der = client_key.serialize_der();
    let pieces: [(&str, &[u8]); 12] = [
        ("ca.crt", ca_pem.as_bytes()),
        ("ca.key", ca_key_pem.as_bytes()),
        ("ca.der", ca_cert.der()),
        ("ca-key.der", &ca_key_der),
        ("server.crt", server_pem.as_bytes()),
        ("server.key", server_key_pem.as_bytes()),
        ("server.der", server_cert.der()),
        ("server-key.der", &server_key_der),
        ("client.crt", client_pem.as_bytes()),
        ("client.key", client_key_pem.as_bytes()),
        ("client.der", client_cert.der()),
        ("client-key.der", &client_key_der),
    ];
    let mut files = Vec::new();
    for (name, bytes) in pieces {
        let path = folder.join(name);
        write(&path, bytes)?;
        files.push(path.display().to_string());
    }
    let header = c_header(&[
        ("ca_crt", ca_pem.as_bytes(), ca_cert.der()),
        ("server_crt", server_pem.as_bytes(), server_cert.der()),
        ("server_key", server_key_pem.as_bytes(), &server_key_der),
        ("client_crt", client_pem.as_bytes(), client_cert.der()),
        ("client_key", client_key_pem.as_bytes(), &client_key_der),
    ]);
    let path = folder.join("certs.h");
    write(&path, header.as_bytes())?;
    files.push(path.display().to_string());

    Ok(MadeSet {
        files,
        ca_sha256: fingerprint(ca_cert.der()),
        server_sha256: fingerprint(server_cert.der()),
        client_sha256: fingerprint(client_cert.der()),
    })
}

/// A C header with each certificate and key twice: as a PEM string, as
/// mbedTLS and ESP-IDF take them, and as DER bytes, with their lengths.
fn c_header(items: &[(&str, &[u8], &[u8])]) -> String {
    let mut out = String::from(
        "/* Test certificates made by netNIMA. Keys for testing only: do not ship them. */\n\n#ifndef NETNIMA_CERTS_H\n#define NETNIMA_CERTS_H\n\n",
    );
    for (name, pem, der) in items {
        out.push_str(&format!("static const char {name}_pem[] =\n"));
        for line in String::from_utf8_lossy(pem).lines() {
            out.push_str(&format!("    \"{line}\\n\"\n"));
        }
        out.push_str(";\n\n");
        out.push_str(&format!(
            "static const unsigned char {name}_der[{}] = {{",
            der.len()
        ));
        for (index, byte) in der.iter().enumerate() {
            if index % 12 == 0 {
                out.push_str("\n    ");
            }
            out.push_str(&format!("0x{byte:02x},"));
            if index % 12 != 11 && index + 1 != der.len() {
                out.push(' ');
            }
        }
        out.push_str(&format!(
            "\n}};\nstatic const unsigned int {name}_der_len = {};\n\n",
            der.len()
        ));
    }
    out.push_str("#endif /* NETNIMA_CERTS_H */\n");
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A folder of its own for one test, emptied first.
    pub(crate) fn scratch(name: &str) -> PathBuf {
        let folder =
            std::env::temp_dir().join(format!("netnima-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        folder
    }

    #[test]
    fn a_set_has_every_file_and_the_ca_signed_the_others() {
        let folder = scratch("set");
        let made = make_set(&SetRequest {
            folder: folder.display().to_string(),
            server_names: vec!["board.local".into(), "192.168.1.50".into()],
            client_name: "sensor-7".into(),
            years: 2,
        })
        .unwrap();
        assert_eq!(made.files.len(), 13);
        let server =
            crate::net::tls::certificates(&folder.join("server.crt").display().to_string())
                .unwrap();
        let info = crate::net::tls::describe(&server[0]);
        assert_eq!(info.names, ["board.local", "192.168.1.50"]);
        assert!(info.issuer.contains("netNIMA test CA"), "{info:?}");
        let client = std::fs::read(folder.join("client.der")).unwrap();
        let info = crate::net::tls::describe(&client);
        assert!(info.subject.contains("sensor-7"), "{info:?}");
        let header = std::fs::read_to_string(folder.join("certs.h")).unwrap();
        assert!(header.contains("static const char ca_crt_pem[] ="));
        assert!(header.contains("client_key_der_len"));
        assert!(header.contains("\"-----BEGIN CERTIFICATE-----\\n\""));
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_set_needs_a_folder_and_a_name() {
        assert!(
            make_set(&SetRequest::default())
                .unwrap_err()
                .contains("folder")
        );
        let request = SetRequest {
            folder: "x".into(),
            server_names: vec![" ".into()],
            ..SetRequest::default()
        };
        assert!(make_set(&request).unwrap_err().contains("name"));
    }

    #[test]
    fn this_computer_has_names_for_its_certificate() {
        let names = local_names();
        assert_eq!(names[0], "localhost");
        assert!(names.contains(&"127.0.0.1".to_string()));
    }
}
