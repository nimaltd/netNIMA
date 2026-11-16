//! Tools > Certificates: test certificates made for devices, netNIMA's own
//! certificate for its TLS servers, and what a certificate file holds.

use netnima_core::certs::{self, MadeSet, SetRequest};
use netnima_core::net::tls::{self, CertInfo};
use serde::Serialize;

/// netNIMA's own server certificate: its files and what it says.
#[derive(Serialize)]
pub struct OwnCertificate {
    cert: String,
    key: String,
    info: Option<CertInfo>,
    problem: Option<String>,
}

/// netNIMA's own server certificate, made now if it was not made yet.
#[tauri::command(async)]
pub fn own_certificate() -> OwnCertificate {
    match certs::own_files() {
        Ok((cert, key)) => {
            let cert = cert.display().to_string();
            let info = tls::read_certificates(&cert)
                .ok()
                .and_then(|found| found.into_iter().next());
            OwnCertificate {
                cert,
                key: key.display().to_string(),
                info,
                problem: None,
            }
        }
        Err(problem) => OwnCertificate {
            cert: String::new(),
            key: String::new(),
            info: None,
            problem: Some(problem),
        },
    }
}

/// The names and addresses a certificate for this computer is for.
#[tauri::command(async)]
pub fn local_names() -> Vec<String> {
    certs::local_names()
}

/// Makes a CA with a server's and a client's certificate, in the folder asked for.
#[tauri::command(async)]
pub fn make_certificates(request: SetRequest) -> Result<MadeSet, String> {
    certs::make_set(&request)
}

/// What the certificates in a PEM or DER file say.
#[tauri::command(async)]
pub fn read_certificates(path: String) -> Result<Vec<CertInfo>, String> {
    tls::read_certificates(&path)
}
