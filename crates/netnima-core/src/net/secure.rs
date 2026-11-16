//! TLS on a connection a protocol makes of its own, such as FTPS's data
//! connections: blocking, on the thread that does the transfer, with the
//! engine the tab's TLS settings need.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use openssl::ssl::{HandshakeError, SslStream};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use super::legacy;
use super::tls::{self, ClientSetup, ServerSetup};

/// A TLS stream that blocks, as a thread of its own reads and writes it.
pub(crate) enum SecureStream {
    RustlsClient(Box<StreamOwned<ClientConnection, TcpStream>>),
    RustlsServer(Box<StreamOwned<ServerConnection, TcpStream>>),
    Openssl(Box<SslStream<TcpStream>>),
}

/// A rustls error that came inside an `io::Error`, in plain words.
fn rustls_words(error: io::Error) -> io::Error {
    let words = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .map(tls::problem);
    match words {
        Some(words) => tls::failed(words),
        None => error,
    }
}

fn openssl_words<S>(error: HandshakeError<S>) -> io::Error {
    match error {
        HandshakeError::Failure(mid) | HandshakeError::WouldBlock(mid) => {
            tls::failed(legacy::problem(mid.error(), Some(mid.ssl())))
        }
        HandshakeError::SetupFailure(stack) => {
            tls::failed(format!("OpenSSL could not start: {stack}"))
        }
    }
}

impl SecureStream {
    /// A client's TLS on `stream`, its handshake done.
    pub(crate) fn client(mut stream: TcpStream, setup: ClientSetup) -> io::Result<Self> {
        match setup {
            ClientSetup::Rustls(config, name) => {
                let mut connection = ClientConnection::new(config, name)
                    .map_err(|error| tls::failed(tls::problem(&error)))?;
                while connection.is_handshaking() {
                    connection.complete_io(&mut stream).map_err(rustls_words)?;
                }
                Ok(Self::RustlsClient(Box::new(StreamOwned::new(
                    connection, stream,
                ))))
            }
            ClientSetup::Openssl(ssl) => {
                let stream = ssl.connect(stream).map_err(openssl_words)?;
                Ok(Self::Openssl(Box::new(stream)))
            }
        }
    }

    /// A server's TLS on `stream`, its handshake done.
    pub(crate) fn server(mut stream: TcpStream, setup: &ServerSetup) -> io::Result<Self> {
        match setup {
            ServerSetup::Rustls(config) => {
                let mut connection = ServerConnection::new(config.clone())
                    .map_err(|error| tls::failed(tls::problem(&error)))?;
                while connection.is_handshaking() {
                    connection.complete_io(&mut stream).map_err(rustls_words)?;
                }
                Ok(Self::RustlsServer(Box::new(StreamOwned::new(
                    connection, stream,
                ))))
            }
            ServerSetup::Openssl(context) => {
                let ssl = legacy::accept(context).map_err(tls::failed)?;
                let stream = ssl.accept(stream).map_err(openssl_words)?;
                Ok(Self::Openssl(Box::new(stream)))
            }
        }
    }

    /// Reads to the end. The other end closing without TLS's goodbye ends it
    /// too, as many devices do.
    pub(crate) fn read_all(&mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match self.read(&mut buf) {
                Ok(0) => return Ok(bytes),
                Ok(count) => bytes.extend_from_slice(&buf[..count]),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(bytes),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Whether its handshake took up an earlier session again.
    pub(crate) fn resumed(&self) -> bool {
        match self {
            Self::RustlsClient(stream) => {
                stream.conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed)
            }
            Self::RustlsServer(stream) => {
                stream.conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed)
            }
            Self::Openssl(stream) => stream.ssl().session_reused(),
        }
    }

    /// The TCP connection under it.
    pub(crate) fn tcp(&self) -> &TcpStream {
        match self {
            Self::RustlsClient(stream) => &stream.sock,
            Self::RustlsServer(stream) => &stream.sock,
            Self::Openssl(stream) => stream.get_ref(),
        }
    }

    /// Says TLS's goodbye (close_notify), so the other end knows all came.
    pub(crate) fn finish(&mut self) {
        match self {
            Self::RustlsClient(stream) => {
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
            Self::RustlsServer(stream) => {
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
            Self::Openssl(stream) => {
                let _ = stream.shutdown();
            }
        }
    }
}

impl Read for SecureStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::RustlsClient(stream) => stream.read(buf),
            Self::RustlsServer(stream) => stream.read(buf),
            Self::Openssl(stream) => match stream.ssl_read(buf) {
                Ok(count) => Ok(count),
                Err(error) if error.code() == openssl::ssl::ErrorCode::ZERO_RETURN => Ok(0),
                Err(error)
                    if error.code() == openssl::ssl::ErrorCode::SYSCALL
                        && error.io_error().is_none() =>
                {
                    Ok(0)
                }
                Err(error) => Err(error
                    .into_io_error()
                    .unwrap_or_else(|error| tls::failed(error.to_string()))),
            },
        }
    }
}

impl Write for SecureStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::RustlsClient(stream) => stream.write(buf),
            Self::RustlsServer(stream) => stream.write(buf),
            Self::Openssl(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::RustlsClient(stream) => stream.flush(),
            Self::RustlsServer(stream) => stream.flush(),
            Self::Openssl(stream) => stream.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::net::{TlsClientOptions, TlsServerOptions, Verify};

    /// Two connections to two servers made with the same settings, as an
    /// FTPS control connection and its data connection are: with
    /// `share_sessions`, the second takes up the first one's session, and
    /// without, it does not.
    #[test]
    fn a_connection_beside_another_takes_up_its_session() {
        assert_eq!(resumed(true), [(false, false), (true, true)]);
        assert_eq!(resumed(false), [(false, false), (false, false)]);
    }

    /// Whether each of two connections, client and server, took up a session.
    fn resumed(share_sessions: bool) -> Vec<(bool, bool)> {
        let server_options = TlsServerOptions {
            share_sessions,
            // A name of its own, so other tests' sessions are not taken up.
            alpn: format!("test-{share_sessions}"),
            ..TlsServerOptions::default()
        };
        let client_options = TlsClientOptions {
            verify: Verify::None,
            share_sessions,
            alpn: format!("test-{share_sessions}"),
            ..TlsClientOptions::default()
        };
        let control = tls::server_setup(&server_options).unwrap();
        let data = tls::server_setup(&server_options).unwrap();
        let mut resumed = Vec::new();
        for setup in [control, data] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut stream = SecureStream::server(stream, &setup).unwrap();
                stream.write_all(b"hello").unwrap();
                stream.finish();
                stream.resumed()
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let setup = tls::client_setup(&client_options, "127.0.0.1").unwrap();
            let mut stream = SecureStream::client(stream, setup).unwrap();
            assert_eq!(stream.read_all().unwrap(), b"hello");
            stream.finish();
            resumed.push((stream.resumed(), server.join().unwrap()));
        }
        resumed
    }
}
