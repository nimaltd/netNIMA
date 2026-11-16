//! TLS on TCP, with rustls: what a client or a server tab sets, the rustls
//! configs made from it, what the two ends agreed, and TLS errors in plain
//! words.
//!
//! TLS 1.2 and 1.3 are done here, in Rust. The older versions, PSK and the
//! CCM suites some small devices need come with an engine of their own.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, OnceLock};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    AlertDescription, CertificateError, ClientConfig, Connection, DigitallySignedStruct,
    DistinguishedName, HandshakeKind, KeyLog, NoKeyLog, ProtocolVersion, RootCertStore,
    ServerConfig, SignatureScheme, SupportedProtocolVersion,
};
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::public_key::PublicKey;

use crate::certs;

/// The TLS versions a tab speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Versions {
    /// 1.2 and 1.3: the other end chooses.
    #[default]
    Both,
    Tls12,
    Tls13,
    /// 1.0 to 1.3, with OpenSSL: for old devices.
    All,
    /// 1.0 only, with OpenSSL.
    Tls10,
    /// 1.1 only, with OpenSSL.
    Tls11,
}

/// Which TLS engine a tab uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// rustls, unless the settings need OpenSSL: old versions, a PSK, or a cipher list.
    #[default]
    Auto,
    Rustls,
    Openssl,
}

static BOTH: [&SupportedProtocolVersion; 2] = [&rustls::version::TLS13, &rustls::version::TLS12];
static ONLY_12: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
static ONLY_13: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

impl Versions {
    fn rustls(self) -> Result<&'static [&'static SupportedProtocolVersion], String> {
        match self {
            Versions::Both => Ok(&BOTH),
            Versions::Tls12 => Ok(&ONLY_12),
            Versions::Tls13 => Ok(&ONLY_13),
            Versions::All | Versions::Tls10 | Versions::Tls11 => Err(
                "rustls speaks TLS 1.2 and 1.3 only: choose the OpenSSL engine, or Auto, for 1.0 and 1.1."
                    .into(),
            ),
        }
    }
}

/// How a client checks the server's certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verify {
    /// Against the certificates this computer trusts, as a browser does.
    #[default]
    System,
    /// Against the certificates in a file, such as a device's own CA.
    File,
    /// Not at all: any certificate is taken, and still shown.
    None,
}

/// Whether a server asks its clients for a certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    /// It does not ask.
    #[default]
    None,
    /// It asks, and takes a client without one; one sent must be signed by the CA.
    Optional,
    /// A client must send one signed by the CA.
    Required,
    /// It asks, and takes any certificate without a check, to see what a
    /// device sends.
    Any,
}

/// A TLS client tab's settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsClientOptions {
    /// How the server's certificate is checked.
    pub verify: Verify,
    /// The certificates to trust, in a PEM or DER file, for `Verify::File`.
    pub ca_file: String,
    /// Whether the certificate must be for the name asked for.
    pub check_name: bool,
    /// The name asked for (SNI) and checked: empty for the host connected to.
    pub server_name: String,
    /// Asks for no name: for servers that turn down a name they do not know.
    pub no_sni: bool,
    /// This end's certificate, for a server that asks for one: PEM or DER.
    pub cert_file: String,
    /// Its private key: empty when it is in the certificate's file.
    pub key_file: String,
    /// The application protocols offered (ALPN), such as "h2, http/1.1" or "mqtt".
    pub alpn: String,
    pub versions: Versions,
    /// A file each connection's keys are added to, for Wireshark to decrypt with.
    pub key_log: String,
    pub engine: Engine,
    /// A pre-shared key instead of certificates, with OpenSSL.
    pub psk: bool,
    /// The identity the server knows this end by.
    pub psk_identity: String,
    /// The key: hex digits, or text in quotes.
    pub psk_key: String,
    /// OpenSSL's names of the suites offered, such as "ECDHE-ECDSA-AES128-CCM8"; empty for all.
    pub ciphers: String,
    /// TLS waits until the protocol asks for it, as FTP's AUTH TLS does: the
    /// connection starts plain. A protocol tab sets it, not the user.
    pub starttls: bool,
    /// Connections with the same settings take up each other's sessions, as
    /// FTPS's data connections take up their control connection's. A
    /// protocol tab sets it, not the user.
    pub share_sessions: bool,
}

impl Default for TlsClientOptions {
    fn default() -> Self {
        Self {
            verify: Verify::System,
            ca_file: String::new(),
            check_name: true,
            server_name: String::new(),
            no_sni: false,
            cert_file: String::new(),
            key_file: String::new(),
            alpn: String::new(),
            versions: Versions::Both,
            key_log: String::new(),
            engine: Engine::Auto,
            psk: false,
            psk_identity: "netnima".into(),
            psk_key: "000102030405060708090a0b0c0d0e0f".into(),
            ciphers: String::new(),
            starttls: false,
            share_sessions: false,
        }
    }
}

/// A TLS server tab's settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsServerOptions {
    /// The server's certificate chain, PEM or DER: empty for netNIMA's own,
    /// made for this computer's names and addresses.
    pub cert_file: String,
    /// Its private key: empty when it is in the certificate's file.
    pub key_file: String,
    pub client_auth: ClientAuth,
    /// The certificates client certificates must be signed by.
    pub ca_file: String,
    /// The application protocols taken (ALPN), the server's choice first.
    pub alpn: String,
    pub versions: Versions,
    /// A file each connection's keys are added to, for Wireshark to decrypt with.
    pub key_log: String,
    pub engine: Engine,
    /// Takes clients with a pre-shared key too, with OpenSSL.
    pub psk: bool,
    /// The identity it takes: empty for any.
    pub psk_identity: String,
    /// The key: hex digits, or text in quotes.
    pub psk_key: String,
    /// OpenSSL's names of the suites taken; empty for all.
    pub ciphers: String,
    /// TLS waits until the protocol asks for it, as FTP's AUTH TLS does: the
    /// connection starts plain. A protocol tab sets it, not the user.
    pub starttls: bool,
    /// Servers with the same settings share their sessions, so an FTPS data
    /// connection can take up its control connection's. A protocol tab sets
    /// it, not the user.
    pub share_sessions: bool,
}

/// What a client connects with: rustls's config and the name it asks for, or
/// OpenSSL's connection.
pub(crate) enum ClientSetup {
    Rustls(Arc<ClientConfig>, ServerName<'static>),
    Openssl(Box<openssl::ssl::Ssl>),
}

/// A client's TLS, with the engine its settings need.
pub(crate) fn client_setup(options: &TlsClientOptions, host: &str) -> Result<ClientSetup, String> {
    if super::legacy::needed(
        options.engine,
        options.versions,
        options.psk,
        &options.ciphers,
    ) {
        return Ok(ClientSetup::Openssl(Box::new(super::legacy::client(
            options, host,
        )?)));
    }
    Ok(ClientSetup::Rustls(
        client_config(options)?,
        server_name(options, host)?,
    ))
}

/// What a server takes clients with: rustls's config or OpenSSL's.
#[derive(Clone)]
pub(crate) enum ServerSetup {
    Rustls(Arc<ServerConfig>),
    Openssl(Arc<openssl::ssl::SslContext>),
}

/// A server's TLS, with the engine its settings need.
pub(crate) fn server_setup(options: &TlsServerOptions) -> Result<ServerSetup, String> {
    if super::legacy::needed(
        options.engine,
        options.versions,
        options.psk,
        &options.ciphers,
    ) {
        return Ok(ServerSetup::Openssl(Arc::new(super::legacy::server(
            options,
        )?)));
    }
    Ok(ServerSetup::Rustls(server_config(options)?))
}

/// What the two ends of a TLS connection agreed in its handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Agreed {
    /// "TLS 1.3" or "TLS 1.2".
    pub version: String,
    /// The cipher suite, such as "TLS13_AES_128_GCM_SHA256".
    pub suite: String,
    /// The key exchange, such as "X25519"; empty when none was named.
    pub group: String,
    /// The application protocol chosen with ALPN; empty when none.
    pub alpn: String,
    /// On a server, the name the client asked for (SNI); empty when none.
    pub name: String,
    /// Whether it took up an earlier session again instead of a full handshake.
    pub resumed: bool,
    /// The other end's certificates, its own first; empty when it sent none.
    pub chain: Vec<CertInfo>,
}

/// A certificate, as people read one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// The names and addresses it is for.
    pub names: Vec<String>,
    /// When it starts and stops being valid, such as "2026-01-31 12:00 UTC".
    pub not_before: String,
    pub not_after: String,
    /// Its key, such as "EC 256 bits" or "RSA 2048 bits".
    pub key: String,
    /// Its SHA-256 fingerprint, "AB:CD:…", to compare with one known.
    pub sha256: String,
}

/// The crypto everything here uses: ring, which builds without NASM on Windows.
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

/// A client tab's rustls config, or what is wrong with its settings.
fn make_client_config(options: &TlsClientOptions) -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let verifier: Arc<dyn ServerCertVerifier> = match options.verify {
        Verify::None => Arc::new(AnyServer(provider.clone())),
        Verify::System => Arc::new(Checker::new(
            system_roots()?,
            options.check_name,
            &provider,
        )?),
        Verify::File => {
            if options.ca_file.trim().is_empty() {
                return Err(
                    "Choose the file of the certificates to trust, or check against this computer's."
                        .into(),
                );
            }
            Arc::new(Checker::new(
                roots(&options.ca_file)?,
                options.check_name,
                &provider,
            )?)
        }
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(options.versions.rustls()?)
        .map_err(|error| format!("TLS cannot be set up: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = if options.cert_file.trim().is_empty() {
        builder.with_no_client_auth()
    } else {
        let (chain, key) = identity(&options.cert_file, &options.key_file)?;
        builder.with_client_auth_cert(chain, key).map_err(|error| {
            format!("This end's certificate cannot be used: {}", problem(&error))
        })?
    };
    config.alpn_protocols = alpn(&options.alpn);
    config.enable_sni = !options.no_sni;
    config.key_log = key_log(&options.key_log)?;
    Ok(Arc::new(config))
}

/// When a file was last changed, so a config made from it is made again
/// after it changes.
fn changed(path: &str) -> Option<std::time::SystemTime> {
    let path = path.trim();
    (!path.is_empty())
        .then(|| {
            std::fs::metadata(path)
                .and_then(|meta| meta.modified())
                .ok()
        })
        .flatten()
}

/// A client's rustls config. With `share_sessions`, connections with the
/// same settings and files get the same one: rustls takes up a session only
/// with the config that made it, and an FTPS data connection must take up
/// its control connection's, as servers such as vsftpd want.
pub(crate) fn client_config(options: &TlsClientOptions) -> Result<Arc<ClientConfig>, String> {
    if !options.share_sessions {
        return make_client_config(options);
    }
    type Made = Vec<(
        (TlsClientOptions, [Option<std::time::SystemTime>; 3]),
        Arc<ClientConfig>,
    )>;
    static MADE: Mutex<Made> = Mutex::new(Vec::new());
    let key = (
        TlsClientOptions {
            starttls: false,
            ..options.clone()
        },
        [
            changed(&options.ca_file),
            changed(&options.cert_file),
            changed(&options.key_file),
        ],
    );
    if let Some((_, config)) = MADE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|(known, _)| *known == key)
    {
        return Ok(config.clone());
    }
    let config = make_client_config(options)?;
    let mut made = MADE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if made.len() >= 16 {
        made.remove(0);
    }
    made.push((key, config.clone()));
    Ok(config)
}

/// The name a client asks for and checks: the one set, or the host's.
pub(crate) fn server_name(
    options: &TlsClientOptions,
    host: &str,
) -> Result<ServerName<'static>, String> {
    let name = if options.server_name.trim().is_empty() {
        host.trim()
    } else {
        options.server_name.trim()
    };
    let name = name.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(name.to_string()).map_err(|_| {
        format!(
            "{name} is not a name a certificate can be for. Enter the server's name in the TLS settings."
        )
    })
}

/// A server tab's rustls config, or what is wrong with its settings.
pub(crate) fn server_config(options: &TlsServerOptions) -> Result<Arc<ServerConfig>, String> {
    let provider = provider();
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(options.versions.rustls()?)
        .map_err(|error| format!("TLS cannot be set up: {error}"))?;
    let builder = match options.client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Any => builder.with_client_cert_verifier(Arc::new(AnyClient(provider))),
        ClientAuth::Optional | ClientAuth::Required => {
            if options.ca_file.trim().is_empty() {
                return Err(
                    "Choose the file of the CA that client certificates must be signed by.".into(),
                );
            }
            let roots = Arc::new(roots(&options.ca_file)?);
            let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider);
            let verifier = if options.client_auth == ClientAuth::Optional {
                verifier.allow_unauthenticated()
            } else {
                verifier
            };
            builder.with_client_cert_verifier(
                verifier
                    .build()
                    .map_err(|error| format!("Client certificates cannot be checked: {error}"))?,
            )
        }
    };
    let (chain, key) = if options.cert_file.trim().is_empty() {
        certs::own()?
    } else {
        identity(&options.cert_file, &options.key_file)?
    };
    let mut config = builder.with_single_cert(chain, key).map_err(|error| {
        format!(
            "The server's certificate cannot be used: {}",
            problem(&error)
        )
    })?;
    config.alpn_protocols = alpn(&options.alpn);
    config.key_log = key_log(&options.key_log)?;
    if options.share_sessions {
        config.session_storage = server_session_store(options);
    }
    Ok(Arc::new(config))
}

/// One store of TLS sessions for all servers with the same settings, made
/// for `share_sessions`: an FTPS data connection takes up its control
/// connection's session.
fn server_session_store(
    options: &TlsServerOptions,
) -> Arc<dyn rustls::server::StoresServerSessions> {
    type Stores = Vec<(
        TlsServerOptions,
        Arc<rustls::server::ServerSessionMemoryCache>,
    )>;
    static STORES: Mutex<Stores> = Mutex::new(Vec::new());
    let key = TlsServerOptions {
        starttls: false,
        key_log: String::new(),
        ..options.clone()
    };
    let mut stores = STORES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, store)) = stores.iter().find(|(known, _)| *known == key) {
        return store.clone();
    }
    if stores.len() >= 32 {
        stores.remove(0);
    }
    let store = rustls::server::ServerSessionMemoryCache::new(256);
    stores.push((key, store.clone()));
    store
}

/// A certificate chain and its key, from PEM or DER files. The key may be in
/// the certificate's file.
pub(crate) fn identity(
    cert_file: &str,
    key_file: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let chain = certificates(cert_file)?;
    let key_file = if key_file.trim().is_empty() {
        cert_file
    } else {
        key_file
    };
    Ok((chain, private_key(key_file)?))
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let path = path.trim();
    std::fs::read(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => format!("There is no file {path}."),
        _ => format!("Could not read {path}: {error}"),
    })
}

fn is_pem(bytes: &[u8]) -> bool {
    bytes.windows(10).any(|window| window == b"-----BEGIN")
}

/// The certificates in a PEM file, or the one in a DER file.
pub(crate) fn certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let bytes = read_file(path)?;
    let path = path.trim();
    if !is_pem(&bytes) {
        // DER starts with an ASN.1 sequence.
        return if bytes.first() == Some(&0x30) {
            Ok(vec![CertificateDer::from(bytes)])
        } else {
            Err(format!("{path} is not a certificate: neither PEM nor DER."))
        };
    }
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<_, _>>()
        .map_err(|error| format!("{path} could not be read as PEM: {error}"))?;
    if chain.is_empty() {
        return Err(format!("{path} has no certificate in it."));
    }
    Ok(chain)
}

/// What the certificates in a PEM or DER file say, the first first.
pub fn read_certificates(path: &str) -> Result<Vec<CertInfo>, String> {
    Ok(certificates(path)?
        .iter()
        .map(|der| describe(der))
        .collect())
}

/// The private key in a PEM or DER file.
fn private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let bytes = read_file(path)?;
    let path = path.trim();
    if is_pem(&bytes) {
        PrivateKeyDer::from_pem_slice(&bytes).map_err(|error| match error {
            pem::Error::NoItemsFound => {
                format!("{path} has no private key in it. Choose the key's own file.")
            }
            error => format!("{path} could not be read as a PEM key: {error}"),
        })
    } else {
        PrivateKeyDer::try_from(bytes)
            .map_err(|_| format!("{path} is not a private key: neither PEM nor DER."))
    }
}

/// The certificates in a file, to trust.
fn roots(path: &str) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(path)? {
        roots.add(certificate).map_err(|error| {
            format!(
                "A certificate in {} cannot be trusted: {}",
                path.trim(),
                problem(&error)
            )
        })?;
    }
    Ok(roots)
}

/// The certificates this computer trusts, read once.
fn system_roots() -> Result<RootCertStore, String> {
    static ROOTS: OnceLock<Result<RootCertStore, String>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let found = rustls_native_certs::load_native_certs();
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(found.certs);
            if roots.is_empty() {
                Err("This computer's trusted certificates could not be read. Choose a file of certificates to trust instead.".into())
            } else {
                Ok(roots)
            }
        })
        .clone()
}

/// "h2, http/1.1" as ALPN takes it.
fn alpn(text: &str) -> Vec<Vec<u8>> {
    text.split([',', ' '])
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.as_bytes().to_vec())
        .collect()
}

fn key_log(path: &str) -> Result<Arc<dyn KeyLog>, String> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(Arc::new(NoKeyLog));
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("Could not open the key log {path}: {error}"))?;
    Ok(Arc::new(FileKeyLog(Mutex::new(file))))
}

/// Adds each connection's secrets to a file in the NSS key log format, the
/// one Wireshark reads to decrypt what it captured.
#[derive(Debug)]
struct FileKeyLog(Mutex<File>);

impl KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!("{label} {} {}\n", hex(client_random), hex(secret));
        if let Ok(mut file) = self.0.lock() {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Checks a server's certificate as webpki does, against the certificates
/// trusted, and takes one made for another name when names are not checked.
#[derive(Debug)]
pub(crate) struct Checker {
    webpki: Arc<WebPkiServerVerifier>,
    names: bool,
}

impl Checker {
    /// A checker for a client's settings: None when nothing is to be checked.
    pub(crate) fn for_options(
        verify: Verify,
        ca_file: &str,
        check_name: bool,
    ) -> Result<Option<Self>, String> {
        let provider = provider();
        match verify {
            Verify::None => Ok(None),
            Verify::System => Ok(Some(Self::new(system_roots()?, check_name, &provider)?)),
            Verify::File => {
                if ca_file.trim().is_empty() {
                    return Err("Choose the file of the certificates to trust, or check against this computer's.".into());
                }
                Ok(Some(Self::new(roots(ca_file)?, check_name, &provider)?))
            }
        }
    }

    /// Checks a server's own certificate, alone, for `name`.
    pub(crate) fn check(&self, der: &[u8], name: &ServerName<'_>) -> Result<(), String> {
        self.verify_server_cert(&CertificateDer::from(der), &[], name, &[], UnixTime::now())
            .map(|_| ())
            .map_err(|error| problem(&error))
    }

    fn new(
        roots: RootCertStore,
        names: bool,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Self, String> {
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|error| format!("Certificates cannot be checked: {error}"))?;
        Ok(Self { webpki, names })
    }
}

impl ServerCertVerifier for Checker {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let checked = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        match checked {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) if !self.names => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

/// The signature schemes offered when nothing is checked: the usual ones,
/// and the old SHA-1 ones some devices still sign with.
fn every_scheme(provider: &CryptoProvider) -> Vec<SignatureScheme> {
    let mut schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    schemes.extend([
        SignatureScheme::RSA_PKCS1_SHA1,
        SignatureScheme::ECDSA_SHA1_Legacy,
    ]);
    schemes
}

/// Takes any server certificate without a check, for a device whose
/// certificate is only looked at. Its details are still shown.
#[derive(Debug)]
struct AnyServer(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        every_scheme(&self.0)
    }
}

/// Asks clients for a certificate and takes any, or none, to see what a
/// device sends.
#[derive(Debug)]
struct AnyClient(Arc<CryptoProvider>);

impl ClientCertVerifier for AnyClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        every_scheme(&self.0)
    }
}

/// What a connection's handshake agreed.
pub(crate) fn agreed(connection: &Connection) -> Agreed {
    let name = match connection {
        Connection::Server(server) => server.server_name().unwrap_or_default().to_string(),
        Connection::Client(_) => String::new(),
    };
    Agreed {
        version: connection
            .protocol_version()
            .map(version_name)
            .unwrap_or_default(),
        suite: connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite()))
            .unwrap_or_default(),
        group: connection
            .negotiated_key_exchange_group()
            .map(|group| format!("{:?}", group.name()))
            .unwrap_or_default(),
        alpn: connection
            .alpn_protocol()
            .map(|alpn| String::from_utf8_lossy(alpn).into_owned())
            .unwrap_or_default(),
        name,
        resumed: matches!(connection.handshake_kind(), Some(HandshakeKind::Resumed)),
        chain: connection
            .peer_certificates()
            .map(|chain| chain.iter().map(|der| describe(der)).collect())
            .unwrap_or_default(),
    }
}

fn version_name(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        other => format!("{other:?}"),
    }
}

/// A certificate's names, dates, key and fingerprint, from its DER bytes.
pub fn describe(der: &[u8]) -> CertInfo {
    let sha256 = fingerprint(der);
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return CertInfo {
            subject: "(a certificate that cannot be read)".into(),
            issuer: String::new(),
            names: Vec::new(),
            not_before: String::new(),
            not_after: String::new(),
            key: String::new(),
            sha256,
        };
    };
    CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        names: names(&cert),
        not_before: date(cert.validity().not_before.timestamp()),
        not_after: date(cert.validity().not_after.timestamp()),
        key: key_text(&cert),
        sha256,
    }
}

/// SHA-256 of some bytes as "AB:CD:…".
pub fn fingerprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn names(cert: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(found)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    found
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((*dns).to_string()),
            GeneralName::IPAddress(bytes) => match bytes.len() {
                4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).ok()?).to_string()),
                16 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).ok()?).to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn key_text(cert: &X509Certificate<'_>) -> String {
    let info = cert.public_key();
    match info.parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA {} bits", rsa.key_size()),
        Ok(PublicKey::EC(point)) => format!("EC {} bits", point.key_size()),
        _ => match info.algorithm.algorithm.to_id_string().as_str() {
            "1.3.101.112" => "Ed25519".into(),
            "1.3.101.113" => "Ed448".into(),
            other => other.to_string(),
        },
    }
}

/// Seconds since 1970 as "2026-01-31 12:00 UTC".
fn date(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

/// A TLS error in plain words, with what to try.
pub(crate) fn problem(error: &rustls::Error) -> String {
    use rustls::Error as E;
    match error {
        E::InvalidCertificate(error) => certificate_problem(error),
        E::AlertReceived(alert) => alert_problem(*alert),
        E::NoCertificatesPresented => {
            "The other end sent no certificate, and one is needed.".into()
        }
        E::InvalidMessage(_)
        | E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. } => {
            "What came is not the TLS this end expects: does the other end speak TLS on this port?"
                .into()
        }
        E::PeerIncompatible(why) => format!(
            "The two ends have no TLS settings in common ({why:?}). Try other TLS versions; for old devices, the engine for them."
        ),
        E::PeerMisbehaved(why) => format!("The other end broke the TLS rules: {why:?}."),
        E::DecryptError => {
            "A record could not be decrypted: the two ends do not have the same keys.".into()
        }
        E::NoApplicationProtocol => {
            "The two ends have no application protocol (ALPN) in common.".into()
        }
        E::General(text) => text.clone(),
        other => format!("TLS failed: {other}"),
    }
}

fn certificate_problem(error: &CertificateError) -> String {
    use CertificateError as C;
    match error {
        C::UnknownIssuer => "The certificate is not signed by one this end trusts. Choose the CA's file in the TLS settings, or do not check certificates.".into(),
        C::NotValidForName => "The certificate is not for the name asked for. Enter the name it is for, or do not check names.".into(),
        C::NotValidForNameContext { expected, presented } => format!(
            "The certificate is for {}, not for {}. Enter the name it is for, or do not check names.",
            if presented.is_empty() { "no name".to_string() } else { presented.join(", ") },
            name_text(expected)
        ),
        C::Expired => "The certificate has expired.".into(),
        C::ExpiredContext { not_after, .. } => format!(
            "The certificate expired on {}.",
            date(not_after.as_secs() as i64)
        ),
        C::NotValidYet => {
            "The certificate is not valid yet: check this computer's clock, and the device's.".into()
        }
        C::NotValidYetContext { not_before, .. } => format!(
            "The certificate is valid from {} only: check this computer's clock, and the device's.",
            date(not_before.as_secs() as i64)
        ),
        C::BadSignature => "The certificate's signature is wrong.".into(),
        C::BadEncoding => "The certificate cannot be read.".into(),
        C::Revoked => "The certificate has been revoked.".into(),
        C::InvalidPurpose | C::InvalidPurposeContext { .. } => {
            "The certificate is not for this use: a server needs one for servers, a client one for clients.".into()
        }
        C::UnsupportedSignatureAlgorithmContext { .. }
        | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
            "The certificate is signed in a way this end does not take, such as with SHA-1. Do not check certificates to connect anyway.".into()
        }
        other => format!("The certificate was turned down: {other:?}."),
    }
}

fn name_text(name: &ServerName<'_>) -> String {
    match name {
        ServerName::DnsName(dns) => dns.as_ref().to_string(),
        ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
        other => format!("{other:?}"),
    }
}

fn alert_problem(alert: AlertDescription) -> String {
    use AlertDescription as A;
    let why = match alert {
        A::HandshakeFailure => "it has no cipher suite or key exchange in common with this end",
        A::ProtocolVersion => "it does not speak the TLS versions this end offers",
        A::InsufficientSecurity => "it wants stronger ciphers than this end offers",
        A::BadCertificate | A::UnsupportedCertificate | A::CertificateUnknown => {
            "it did not take this end's certificate"
        }
        A::UnknownCA => "it does not trust the CA that signed this end's certificate",
        A::CertificateExpired => "this end's certificate has expired",
        A::CertificateRequired => {
            "it wants a certificate from this end: choose one in the TLS settings"
        }
        A::UnrecognisedName => "it does not know the name asked for (SNI)",
        A::NoApplicationProtocol => "it speaks none of the application protocols (ALPN) offered",
        A::AccessDenied => "it denied access",
        A::DecryptError => "a signature or a key did not check out",
        _ => return format!("The other end ended TLS with the alert {alert:?}."),
    };
    format!("The other end ended TLS: {why}.")
}

/// A TLS failure in words, carried in an `io::Error`.
#[derive(Debug)]
struct TlsFailed(String);

impl std::fmt::Display for TlsFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TlsFailed {}

/// An `io::Error` that says a TLS failure in words.
pub(crate) fn failed(words: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, TlsFailed(words))
}

/// The words of a TLS failure an `io::Error` carries, if it carries one.
pub(crate) fn words(error: &io::Error) -> Option<String> {
    let inner = error.get_ref()?;
    if let Some(failed) = inner.downcast_ref::<TlsFailed>() {
        return Some(failed.0.clone());
    }
    inner.downcast_ref::<rustls::Error>().map(problem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_names_are_split_on_commas_and_spaces() {
        assert_eq!(
            alpn(" h2, http/1.1 mqtt"),
            [b"h2".to_vec(), b"http/1.1".to_vec(), b"mqtt".to_vec()]
        );
        assert!(alpn("").is_empty());
    }

    #[test]
    fn a_name_or_an_address_can_be_asked_for() {
        let options = TlsClientOptions::default();
        assert!(matches!(
            server_name(&options, "board.local").unwrap(),
            ServerName::DnsName(_)
        ));
        assert!(matches!(
            server_name(&options, "[::1]").unwrap(),
            ServerName::IpAddress(_)
        ));
        let named = TlsClientOptions {
            server_name: "device".into(),
            ..TlsClientOptions::default()
        };
        assert!(matches!(
            server_name(&named, "10.0.0.5").unwrap(),
            ServerName::DnsName(name) if name.as_ref() == "device"
        ));
        assert!(server_name(&options, "no_such name").is_err());
    }

    #[test]
    fn missing_files_are_said_in_words() {
        let options = TlsClientOptions {
            verify: Verify::File,
            ca_file: "/no/such/ca.pem".into(),
            ..TlsClientOptions::default()
        };
        let problem = client_config(&options).unwrap_err();
        assert!(problem.contains("There is no file"), "{problem}");
        let none = TlsClientOptions {
            verify: Verify::File,
            ..TlsClientOptions::default()
        };
        assert!(
            client_config(&none)
                .unwrap_err()
                .contains("Choose the file")
        );
        let server = TlsServerOptions {
            client_auth: ClientAuth::Required,
            ..TlsServerOptions::default()
        };
        assert!(server_config(&server).unwrap_err().contains("CA"));
    }

    #[test]
    fn a_server_with_no_certificate_chosen_uses_netnimas_own() {
        assert!(server_config(&TlsServerOptions::default()).is_ok());
        let (chain, _) = certs::own().unwrap();
        let info = describe(&chain[0]);
        assert!(info.names.contains(&"localhost".to_string()), "{info:?}");
        assert!(info.names.contains(&"127.0.0.1".to_string()), "{info:?}");
        assert_eq!(info.key, "EC 256 bits");
        assert_eq!(info.sha256.len(), 32 * 3 - 1);
    }

    #[test]
    fn errors_are_said_in_words() {
        let unknown = rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer);
        assert!(problem(&unknown).contains("not signed by one this end trusts"));
        let alert = rustls::Error::AlertReceived(AlertDescription::CertificateRequired);
        assert!(problem(&alert).contains("wants a certificate"));
        let carried = failed("plain words".into());
        assert_eq!(words(&carried).unwrap(), "plain words");
        assert_eq!(words(&io::Error::from(io::ErrorKind::TimedOut)), None);
    }

    #[test]
    fn settings_read_back_from_toml() {
        let options = TlsClientOptions {
            verify: Verify::None,
            alpn: "mqtt".into(),
            versions: Versions::Tls12,
            ..TlsClientOptions::default()
        };
        let text = toml::to_string(&options).unwrap();
        assert!(text.contains("verify = \"none\""), "{text}");
        assert_eq!(toml::from_str::<TlsClientOptions>(&text).unwrap(), options);
        let partial: TlsClientOptions = toml::from_str("verify = \"file\"").unwrap();
        assert!(partial.check_name);
    }
}
