//! The engine for old and small devices: OpenSSL, built into netNIMA. It
//! speaks what rustls does not: TLS 1.0 and 1.1, the old CBC and RSA
//! suites, pre-shared keys (PSK), and the AES-CCM suites, besides TLS 1.2
//! and 1.3. A tab uses it when its settings need one of those, or when it
//! is chosen. Over UDP it speaks DTLS 1.0 and 1.2: see [`datagram`].

mod datagram;

pub(crate) use datagram::{DtlsSetup, OldDtls, Seen};

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::{Mutex, OnceLock};

use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    AlpnError, NameType, Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslRef,
    SslVerifyMode, SslVersion,
};
use openssl::x509::X509;

use super::dtls::psk_key;
use super::tls::{
    self, Agreed, ClientAuth, Engine, TlsClientOptions, TlsServerOptions, Verify, Versions,
};

/// TLS 1.3's suites, the CCM ones too, which OpenSSL leaves out unless asked.
const TLS13_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";

/// Every suite OpenSSL has, the old and weak ones too: a tester must reach
/// what devices still speak. Security level 0 lets TLS 1.0 and SHA-1 through.
const ALL_SUITES: &str = "ALL:@SECLEVEL=0";

/// Whether a client's settings need OpenSSL rather than rustls.
pub(crate) fn needed(engine: Engine, versions: Versions, psk: bool, ciphers: &str) -> bool {
    match engine {
        Engine::Openssl => true,
        Engine::Rustls => false,
        Engine::Auto => {
            psk || !ciphers.trim().is_empty()
                || matches!(versions, Versions::All | Versions::Tls10 | Versions::Tls11)
        }
    }
}

fn versions(versions: Versions) -> (SslVersion, SslVersion) {
    match versions {
        Versions::Both => (SslVersion::TLS1_2, SslVersion::TLS1_3),
        Versions::Tls12 => (SslVersion::TLS1_2, SslVersion::TLS1_2),
        Versions::Tls13 => (SslVersion::TLS1_3, SslVersion::TLS1_3),
        Versions::All => (SslVersion::TLS1, SslVersion::TLS1_3),
        Versions::Tls10 => (SslVersion::TLS1, SslVersion::TLS1),
        Versions::Tls11 => (SslVersion::TLS1_1, SslVersion::TLS1_1),
    }
}

fn stack(what: &str) -> impl Fn(ErrorStack) -> String + '_ {
    move |error| format!("OpenSSL could not {what}: {error}")
}

/// The settings both ends share: versions, suites, and a key log.
fn common(
    builder: &mut SslContextBuilder,
    (min, max): (SslVersion, SslVersion),
    ciphers: &str,
    psk: bool,
    key_log: &str,
) -> Result<(), String> {
    builder
        .set_min_proto_version(Some(min))
        .map_err(stack("set the versions"))?;
    builder
        .set_max_proto_version(Some(max))
        .map_err(stack("set the versions"))?;
    builder.set_security_level(0);
    // Old servers that do not know secure renegotiation are still talked to:
    // SSL_OP_LEGACY_SERVER_CONNECT, which rust-openssl does not name.
    builder.set_options(
        SslOptions::from_bits_retain(0x4) | SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
    );
    let (old, new): (Vec<&str>, Vec<&str>) = ciphers
        .split([':', ',', ' '])
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .partition(|name| !(name.starts_with("TLS_AES") || name.starts_with("TLS_CHACHA")));
    let list = if !old.is_empty() {
        format!("{}:@SECLEVEL=0", old.join(":"))
    } else if psk {
        // A PSK tab offers PSK suites, so the other end does not pick a certificate one.
        "PSK:@SECLEVEL=0".to_string()
    } else {
        ALL_SUITES.to_string()
    };
    builder
        .set_cipher_list(&list)
        .map_err(|_| format!("OpenSSL knows none of the suites {list:?}: use its names, such as ECDHE-ECDSA-AES128-CCM8 or PSK-AES128-CCM8."))?;
    let suites = if new.is_empty() {
        TLS13_SUITES.to_string()
    } else {
        new.join(":")
    };
    builder
        .set_ciphersuites(&suites)
        .map_err(|_| format!("OpenSSL knows none of the TLS 1.3 suites {suites:?}."))?;
    let path = key_log.trim();
    if !path.is_empty() {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("Could not open the key log {path}: {error}"))?;
        let file = Mutex::new(file);
        builder.set_keylog_callback(move |_, line| {
            if let Ok(mut file) = file.lock() {
                let _ = writeln!(file, "{line}");
            }
        });
    }
    Ok(())
}

/// The ALPN names as TLS sends them: each with its length in front.
fn alpn_wire(text: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for name in text
        .split([',', ' '])
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        wire.push(name.len().min(255) as u8);
        wire.extend_from_slice(&name.as_bytes()[..name.len().min(255)]);
    }
    wire
}

/// A certificate chain and its key from files, as OpenSSL takes them.
fn identity(cert_file: &str, key_file: &str) -> Result<(Vec<X509>, PKey<Private>), String> {
    let (chain, key) = tls::identity(cert_file, key_file)?;
    to_openssl(&chain, key.secret_der())
}

fn to_openssl(
    chain: &[rustls::pki_types::CertificateDer<'_>],
    key: &[u8],
) -> Result<(Vec<X509>, PKey<Private>), String> {
    let chain = chain
        .iter()
        .map(|der| {
            X509::from_der(der)
                .map_err(|error| format!("OpenSSL cannot read a certificate: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key = PKey::private_key_from_pkcs8(key)
        .or_else(|_| PKey::private_key_from_der(key))
        .map_err(|error| format!("OpenSSL cannot read the private key: {error}"))?;
    Ok((chain, key))
}

fn use_identity(
    builder: &mut SslContextBuilder,
    chain: Vec<X509>,
    key: &PKey<Private>,
) -> Result<(), String> {
    let mut certificates = chain.into_iter();
    let first = certificates
        .next()
        .ok_or("The certificate file has no certificate.")?;
    builder
        .set_certificate(&first)
        .map_err(stack("use the certificate"))?;
    for extra in certificates {
        builder
            .add_extra_chain_cert(extra)
            .map_err(stack("use the certificate chain"))?;
    }
    builder
        .set_private_key(key)
        .map_err(stack("use the private key"))?;
    builder
        .check_private_key()
        .map_err(|_| "The private key is not the certificate's.".to_string())
}

/// The certificates this computer trusts, as DER, read once.
fn system_roots() -> &'static [Vec<u8>] {
    static ROOTS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        rustls_native_certs::load_native_certs()
            .certs
            .into_iter()
            .map(|der| der.to_vec())
            .collect()
    })
}

fn trust(builder: &mut SslContextBuilder, verify: Verify, ca_file: &str) -> Result<(), String> {
    let roots: Vec<Vec<u8>> = match verify {
        Verify::None => return Ok(()),
        Verify::System => system_roots().to_vec(),
        Verify::File => {
            if ca_file.trim().is_empty() {
                return Err("Choose the file of the certificates to trust, or check against this computer's.".into());
            }
            tls::certificates(ca_file)?
                .iter()
                .map(|der| der.to_vec())
                .collect()
        }
    };
    let store = builder.cert_store_mut();
    for der in roots {
        if let Ok(certificate) = X509::from_der(&der) {
            let _ = store.add_cert(certificate);
        }
    }
    Ok(())
}

/// The PSK identity a server took, kept on its connection to be shown.
fn identity_index() -> Index<Ssl, String> {
    static INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("OpenSSL gives an ex_data index"))
}

/// How a client checks the server's certificate: against the roots chosen,
/// or not at all.
fn client_trust(
    builder: &mut SslContextBuilder,
    verify: Verify,
    ca_file: &str,
) -> Result<(), String> {
    trust(builder, verify, ca_file)?;
    builder.set_verify(if verify == Verify::None {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });
    Ok(())
}

/// A client's PSK: the identity it gives, kept on the connection to be shown,
/// and the key.
fn psk_client(builder: &mut SslContextBuilder, identity: &str, key: &str) -> Result<(), String> {
    let key = psk_key(key)?;
    let identity = identity.trim().as_bytes().to_vec();
    if identity.is_empty() {
        return Err("Enter the PSK identity the server knows this end by.".into());
    }
    let index = identity_index();
    builder.set_psk_client_callback(move |ssl, _hint, identity_out, key_out| {
        if identity.len() >= identity_out.len() || key.len() > key_out.len() {
            return Err(ErrorStack::get());
        }
        ssl.set_ex_data(index, String::from_utf8_lossy(&identity).into_owned());
        identity_out[..identity.len()].copy_from_slice(&identity);
        identity_out[identity.len()] = 0;
        key_out[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });
    Ok(())
}

/// A server's PSK: the key for the identity set, or for any when none is.
fn psk_server(builder: &mut SslContextBuilder, identity: &str, key: &str) -> Result<(), String> {
    let key = psk_key(key)?;
    let expected = identity.trim().as_bytes().to_vec();
    let index = identity_index();
    builder.set_psk_server_callback(move |ssl, identity, key_out| {
        let identity = identity.unwrap_or_default();
        if !(expected.is_empty() || identity == expected.as_slice()) || key.len() > key_out.len() {
            // 0 bytes: the identity is not known, and the handshake fails.
            return Ok(0);
        }
        ssl.set_ex_data(index, String::from_utf8_lossy(identity).into_owned());
        key_out[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });
    Ok(())
}

/// The name a client asks for (SNI) and checks the server's certificate for:
/// an address is checked as one, and not sent as a name.
fn names(ssl: &mut Ssl, name: &str, sni: bool, check: bool) -> Result<(), String> {
    let name = name.trim().trim_start_matches('[').trim_end_matches(']');
    let ip = name.parse::<IpAddr>().ok();
    if sni && ip.is_none() && !name.is_empty() {
        ssl.set_hostname(name)
            .map_err(stack("ask for the name (SNI)"))?;
    }
    if check {
        match ip {
            Some(ip) => ssl
                .param_mut()
                .set_ip(ip)
                .map_err(stack("check the address"))?,
            None => ssl
                .param_mut()
                .set_host(name)
                .map_err(stack("check the name"))?,
        }
    }
    Ok(())
}

/// A client's connection, ready for its handshake with `host`.
pub(crate) fn client(options: &TlsClientOptions, host: &str) -> Result<Ssl, String> {
    let mut builder = SslContext::builder(SslMethod::tls_client()).map_err(stack("start"))?;
    common(
        &mut builder,
        versions(options.versions),
        &options.ciphers,
        options.psk,
        &options.key_log,
    )?;
    client_trust(&mut builder, options.verify, &options.ca_file)?;
    if !options.cert_file.trim().is_empty() {
        let (chain, key) = identity(&options.cert_file, &options.key_file)?;
        use_identity(&mut builder, chain, &key)?;
    }
    if options.psk {
        psk_client(&mut builder, &options.psk_identity, &options.psk_key)?;
    }
    let wire = alpn_wire(&options.alpn);
    if !wire.is_empty() {
        builder
            .set_alpn_protos(&wire)
            .map_err(stack("offer ALPN"))?;
    }
    let context = builder.build();
    let mut ssl = Ssl::new(&context).map_err(stack("make a connection"))?;
    let name = if options.server_name.trim().is_empty() {
        host
    } else {
        &options.server_name
    };
    names(
        &mut ssl,
        name,
        !options.no_sni,
        options.verify != Verify::None && options.check_name && !options.psk,
    )?;
    ssl.set_connect_state();
    Ok(ssl)
}

/// This end's certificate and key for a server: the files set, or netNIMA's own.
fn server_identity(
    builder: &mut SslContextBuilder,
    cert_file: &str,
    key_file: &str,
) -> Result<(), String> {
    let (chain, key) = if cert_file.trim().is_empty() {
        let (chain, key) = crate::certs::own()?;
        to_openssl(&chain, key.secret_der())?
    } else {
        identity(cert_file, key_file)?
    };
    use_identity(builder, chain, &key)
}

/// A server's settings, from which each client's connection is made.
pub(crate) fn server(options: &TlsServerOptions) -> Result<SslContext, String> {
    let mut builder = SslContext::builder(SslMethod::tls_server()).map_err(stack("start"))?;
    // A server with a PSK still takes certificate clients: all suites stay on.
    common(
        &mut builder,
        versions(options.versions),
        &options.ciphers,
        false,
        &options.key_log,
    )?;
    server_identity(&mut builder, &options.cert_file, &options.key_file)?;
    match options.client_auth {
        ClientAuth::None => builder.set_verify(SslVerifyMode::NONE),
        ClientAuth::Any => builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true),
        ClientAuth::Optional | ClientAuth::Required => {
            trust(&mut builder, Verify::File, &options.ca_file)?;
            let mode = if options.client_auth == ClientAuth::Required {
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
            } else {
                SslVerifyMode::PEER
            };
            builder.set_verify(mode);
        }
    }
    if options.psk {
        psk_server(&mut builder, &options.psk_identity, &options.psk_key)?;
    }
    let names: Vec<Vec<u8>> = options
        .alpn
        .split([',', ' '])
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.as_bytes().to_vec())
        .collect();
    if !names.is_empty() {
        builder.set_alpn_select_callback(move |_, offered| {
            choose_alpn(&names, offered).ok_or(AlpnError::NOACK)
        });
    }
    Ok(builder.build())
}

/// The first of the server's ALPN names that the client offered, as a slice
/// of what it offered, which is what OpenSSL wants back.
fn choose_alpn<'a>(ours: &[Vec<u8>], offered: &'a [u8]) -> Option<&'a [u8]> {
    let mut theirs = Vec::new();
    let mut at = 0;
    while at < offered.len() {
        let length = usize::from(offered[at]);
        theirs.push(offered.get(at + 1..at + 1 + length)?);
        at += 1 + length;
    }
    ours.iter().find_map(|want| {
        theirs
            .iter()
            .find(|have| **have == want.as_slice())
            .copied()
    })
}

/// A connection for a client that came to a server.
pub(crate) fn accept(context: &SslContext) -> Result<Ssl, String> {
    let mut ssl = Ssl::new(context).map_err(stack("take a client"))?;
    ssl.set_accept_state();
    Ok(ssl)
}

/// What a connection's handshake agreed.
pub(crate) fn agreed(ssl: &SslRef) -> Agreed {
    let version = match ssl.version_str() {
        "TLSv1" => "TLS 1.0".to_string(),
        "TLSv1.1" => "TLS 1.1".into(),
        "TLSv1.2" => "TLS 1.2".into(),
        "TLSv1.3" => "TLS 1.3".into(),
        "DTLSv1" => "DTLS 1.0".into(),
        "DTLSv1.2" => "DTLS 1.2".into(),
        other => other.to_string(),
    };
    let suite = ssl
        .current_cipher()
        .map(|cipher| cipher.standard_name().unwrap_or(cipher.name()).to_string())
        .unwrap_or_default();
    let mut chain = Vec::new();
    if let Some(certificate) = ssl.peer_certificate()
        && let Ok(der) = certificate.to_der()
    {
        chain.push(tls::describe(&der));
    }
    if let Some(stack) = ssl.peer_cert_chain() {
        for certificate in stack {
            if let Ok(der) = certificate.to_der() {
                let info = tls::describe(&der);
                if !chain.iter().any(|known| known.sha256 == info.sha256) {
                    chain.push(info);
                }
            }
        }
    }
    let name = match ssl.ex_data(identity_index()) {
        Some(identity) => format!("PSK identity {identity}"),
        None => ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string(),
    };
    Agreed {
        version: format!("{version} (OpenSSL)"),
        suite,
        group: String::new(),
        alpn: ssl
            .selected_alpn_protocol()
            .map(|alpn| String::from_utf8_lossy(alpn).into_owned())
            .unwrap_or_default(),
        name,
        resumed: ssl.session_reused(),
        chain,
    }
}

/// An OpenSSL error in plain words, with what to try.
pub(crate) fn problem(error: &openssl::ssl::Error, ssl: Option<&SslRef>) -> String {
    words(error, ssl, "TLS")
}

/// An OpenSSL error in plain words, for TLS or DTLS.
fn words(error: &openssl::ssl::Error, ssl: Option<&SslRef>, protocol: &str) -> String {
    let reasons: Vec<String> = error
        .ssl_error()
        .map(|stack| {
            stack
                .errors()
                .iter()
                .filter_map(|error| error.reason().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let reason = reasons.join("; ");
    let lower = reason.to_lowercase();
    if lower.contains("certificate verify failed") {
        let why = ssl
            .map(|ssl| ssl.verify_result().error_string())
            .unwrap_or("it could not be checked");
        return format!(
            "The other end's certificate was turned down: {why}. Choose the CA's file, or do not check certificates."
        );
    }
    let words = if lower.contains("wrong version number")
        || lower.contains("packet length too long")
        || lower.contains("record layer failure")
    {
        format!(
            "What came is not the {protocol} this end expects: does the other end speak {protocol} on this port?"
        )
    } else if lower.contains("unsupported protocol")
        || lower.contains("protocol version")
        || lower.contains("no protocols available")
    {
        format!(
            "The two ends have no {protocol} version in common: try another in the {protocol} settings."
        )
    } else if lower.contains("no shared cipher")
        || lower.contains("handshake failure")
        || lower.contains("no cipher")
    {
        "The two ends have no cipher suite in common: try another, or all of them.".into()
    } else if lower.contains("psk") || lower.contains("bad record mac") || lower.contains("decrypt")
    {
        "The PSK was turned down: check the identity and the key on both ends.".into()
    } else if lower.contains("certificate required")
        || lower.contains("peer did not return a certificate")
    {
        format!("A certificate is needed from the client: choose one in the {protocol} settings.")
    } else if lower.contains("unknown ca") || lower.contains("bad certificate") {
        "The other end did not take this end's certificate.".into()
    } else if reason.is_empty() {
        return match error.io_error() {
            Some(io) => format!("The connection broke: {io}"),
            None => format!("{protocol} failed, and OpenSSL did not say why."),
        };
    } else {
        return format!("{protocol} failed (OpenSSL): {reason}");
    };
    format!("{words} (OpenSSL: {reason})")
}

/// A socket as OpenSSL reads it: a read that waited out its timeout is
/// "try again later", not an error, so the session can do its other work.
pub(crate) struct Pipe(pub TcpStream);

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buf) {
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                Err(io::ErrorKind::WouldBlock.into())
            }
            other => other,
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
