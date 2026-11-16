//! A TCP connection's bytes, plain or through TLS, for clients and servers alike.
//!
//! The socket under it does not block: a read gives `WouldBlock` when
//! nothing came, and the session goes on to its other work, then waits for
//! the socket and for commands together.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use openssl::ssl::{ErrorCode, SslStream};
use rustls::{ClientConnection, Connection, ServerConnection};

use super::legacy::{self, Pipe};
use super::tls::{self, Agreed, ClientSetup, ServerSetup};

/// How long a TLS handshake may take before the connection is given up.
pub(crate) const HANDSHAKE_TIME: Duration = Duration::from_secs(10);

/// How long a write may wait for room before the connection is given up.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

const CLOSED_IN_HANDSHAKE: &str = "The other end closed the connection in the TLS handshake: it may not speak TLS, or it turned this end's settings down.";

/// A connection over OpenSSL, the engine for old and small devices.
struct OldTls {
    stream: SslStream<Pipe>,
    /// What was sent before the handshake ended, sent when it does.
    waiting: Vec<u8>,
}

/// A connection: its socket, with TLS on it when the tab speaks TLS.
pub(crate) struct Link {
    stream: TcpStream,
    tls: Option<Box<Connection>>,
    old: Option<Box<OldTls>>,
    /// rustls: what was sent before the handshake ended, sent when it does.
    waiting: Vec<u8>,
    /// When it connected, for the handshake's time limit.
    since: Instant,
    /// Whether what TLS agreed has been told.
    told: bool,
}

impl Link {
    pub(crate) fn plain(stream: TcpStream) -> Self {
        Self {
            stream,
            tls: None,
            old: None,
            waiting: Vec::new(),
            since: Instant::now(),
            told: false,
        }
    }

    /// A client's connection, which starts its TLS handshake.
    pub(crate) fn client(stream: TcpStream, setup: ClientSetup) -> io::Result<Self> {
        match setup {
            ClientSetup::Rustls(config, name) => {
                let connection = ClientConnection::new(config, name)
                    .map_err(|error| tls::failed(tls::problem(&error)))?;
                Ok(Self {
                    tls: Some(Box::new(connection.into())),
                    ..Self::plain(stream)
                })
            }
            // The ClientHello goes with the first read, as rustls's does, so a
            // handshake that fails ends the connection like any other loss.
            ClientSetup::Openssl(ssl) => Self::over_openssl(stream, *ssl),
        }
    }

    /// A server's client, whose TLS handshake it waits for.
    pub(crate) fn server(stream: TcpStream, setup: &ServerSetup) -> io::Result<Self> {
        match setup {
            ServerSetup::Rustls(config) => {
                let connection = ServerConnection::new(config.clone())
                    .map_err(|error| tls::failed(tls::problem(&error)))?;
                Ok(Self {
                    tls: Some(Box::new(connection.into())),
                    ..Self::plain(stream)
                })
            }
            ServerSetup::Openssl(context) => {
                let ssl = legacy::accept(context).map_err(tls::failed)?;
                Self::over_openssl(stream, ssl)
            }
        }
    }

    /// A plain client connection that starts TLS now, as FTP's AUTH TLS asks.
    pub(crate) fn start_client(&mut self, setup: ClientSetup) -> io::Result<()> {
        self.not_yet_secure()?;
        *self = Self::client(self.stream.try_clone()?, setup)?;
        Ok(())
    }

    /// A plain server connection that starts TLS now, as FTP's AUTH TLS asks.
    pub(crate) fn start_server(&mut self, setup: &ServerSetup) -> io::Result<()> {
        self.not_yet_secure()?;
        *self = Self::server(self.stream.try_clone()?, setup)?;
        Ok(())
    }

    fn not_yet_secure(&self) -> io::Result<()> {
        if self.tls.is_some() || self.old.is_some() {
            return Err(tls::failed(
                "TLS was asked for again on a connection that has it.".into(),
            ));
        }
        Ok(())
    }

    fn over_openssl(stream: TcpStream, ssl: openssl::ssl::Ssl) -> io::Result<Self> {
        let pipe = Pipe(stream.try_clone()?);
        let stream_over = SslStream::new(ssl, pipe)
            .map_err(|error| tls::failed(format!("OpenSSL could not start: {error}")))?;
        Ok(Self {
            old: Some(Box::new(OldTls {
                stream: stream_over,
                waiting: Vec::new(),
            })),
            ..Self::plain(stream)
        })
    }

    /// Moves an OpenSSL handshake on as far as it can go now; sends what
    /// waited for it when it ends.
    fn handshake(&mut self) -> io::Result<()> {
        let Some(old) = self.old.as_deref_mut() else {
            return Ok(());
        };
        if old.stream.ssl().is_init_finished() {
            return Ok(());
        }
        match old.stream.do_handshake() {
            Ok(()) => {
                let waiting = std::mem::take(&mut old.waiting);
                if !waiting.is_empty() {
                    self.write_all(&waiting)?;
                }
                Ok(())
            }
            Err(error) if matches!(error.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {
                Ok(())
            }
            Err(error) => {
                let words = legacy::problem(&error, Some(old.stream.ssl()));
                Err(tls::failed(words))
            }
        }
    }

    fn old_handshaking(&self) -> bool {
        self.old
            .as_ref()
            .is_some_and(|old| !old.stream.ssl().is_init_finished())
    }

    pub(crate) fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// What TLS agreed, once, when its handshake has just ended.
    pub(crate) fn agreed(&mut self) -> Option<Agreed> {
        if let Some(old) = self.old.as_deref() {
            if self.told || !old.stream.ssl().is_init_finished() {
                return None;
            }
            self.told = true;
            return Some(legacy::agreed(old.stream.ssl()));
        }
        let tls = self.tls.as_deref()?;
        if self.told || tls.is_handshaking() {
            return None;
        }
        self.told = true;
        Some(tls::agreed(tls))
    }

    /// Whether the TLS handshake has gone on too long: the other end may not speak TLS.
    pub(crate) fn handshake_overdue(&self) -> bool {
        (self.tls.as_ref().is_some_and(|tls| tls.is_handshaking()) || self.old_handshaking())
            && self.since.elapsed() >= HANDSHAKE_TIME
    }

    /// Reads what came: the plain bytes, through TLS when it is on. 0 when
    /// the other end closed the connection.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.old.is_some() {
            return self.read_openssl(buf);
        }
        loop {
            // What waited for the handshake goes as soon as it has ended,
            // here in the read that ended it.
            if !self.waiting.is_empty()
                && self.tls.as_ref().is_some_and(|tls| !tls.is_handshaking())
            {
                let waiting = std::mem::take(&mut self.waiting);
                self.write_all(&waiting)?;
            }
            let Some(tls) = self.tls.as_deref_mut() else {
                return self.stream.read(buf);
            };
            match tls.reader().read(buf) {
                Ok(count) => return Ok(count),
                // Nothing decrypted yet: read records below.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                // Closed without TLS's goodbye, which many devices leave out.
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return if tls.is_handshaking() {
                        Err(tls::failed(CLOSED_IN_HANDSHAKE.into()))
                    } else {
                        Ok(0)
                    };
                }
                Err(error) => return Err(error),
            }
            // What the handshake has to send goes before waiting for an answer.
            flush(tls, &mut self.stream)?;
            tls.read_tls(&mut self.stream)?;
            let processed = tls.process_new_packets();
            // The alert that says why goes out even when what came was bad.
            let sent = flush(tls, &mut self.stream);
            if let Err(error) = processed {
                return Err(tls::failed(tls::problem(&error)));
            }
            sent?;
        }
    }

    fn read_openssl(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.old_handshaking() {
            self.handshake()?;
            if self.old_handshaking() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let Some(old) = self.old.as_deref_mut() else {
            return Ok(0);
        };
        match old.stream.ssl_read(buf) {
            Ok(count) => Ok(count),
            Err(error) => match error.code() {
                // The other end's goodbye (close_notify).
                ErrorCode::ZERO_RETURN => Ok(0),
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                    Err(io::ErrorKind::WouldBlock.into())
                }
                // The socket ended without TLS's goodbye.
                ErrorCode::SYSCALL if error.io_error().is_none() => Ok(0),
                ErrorCode::SYSCALL => Err(error
                    .into_io_error()
                    .unwrap_or_else(|error| tls::failed(error.to_string()))),
                _ => {
                    let words = legacy::problem(&error, Some(old.stream.ssl()));
                    Err(tls::failed(words))
                }
            },
        }
    }

    fn write_openssl(&mut self, data: &[u8]) -> io::Result<()> {
        if self.old_handshaking() {
            if let Some(old) = self.old.as_deref_mut() {
                old.waiting.extend_from_slice(data);
            }
            return self.handshake();
        }
        let Some(old) = self.old.as_deref_mut() else {
            return Ok(());
        };
        let mut until = Instant::now() + WRITE_TIMEOUT;
        let mut rest = data;
        while !rest.is_empty() {
            match old.stream.ssl_write(rest) {
                Ok(count) => {
                    rest = &rest[count..];
                    until = Instant::now() + WRITE_TIMEOUT;
                }
                Err(error)
                    if matches!(error.code(), ErrorCode::WANT_WRITE | ErrorCode::WANT_READ) =>
                {
                    if Instant::now() >= until {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the other end did not take what was sent for 5 s",
                        ));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => {
                    let words = legacy::problem(&error, Some(old.stream.ssl()));
                    return Err(tls::failed(words));
                }
            }
        }
        Ok(())
    }

    /// Sends all of `data`, through TLS when it is on.
    pub(crate) fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        if self.old.is_some() {
            return self.write_openssl(data);
        }
        let Some(tls) = self.tls.as_deref_mut() else {
            return write_waiting(&mut self.stream, data);
        };
        // Before the handshake ends, rustls holds only 64 KB: the rest waits here.
        if tls.is_handshaking() {
            self.waiting.extend_from_slice(data);
            return Ok(());
        }
        let mut rest = data;
        while !rest.is_empty() {
            let count = tls.writer().write(rest)?;
            rest = &rest[count..];
            flush(tls, &mut self.stream)?;
            if count == 0 {
                return Err(tls::failed(
                    "The TLS handshake has not ended, and what waits to be sent after it fills its buffer."
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// Says TLS's goodbye (close_notify) before the connection closes.
    pub(crate) fn close(&mut self) {
        if let Some(old) = self.old.as_deref_mut() {
            let _ = old.stream.shutdown();
        }
        if let Some(tls) = self.tls.as_deref_mut() {
            tls.send_close_notify();
            let _ = flush(tls, &mut self.stream);
        }
    }
}

/// Sends what TLS has to send.
fn flush(tls: &mut Connection, stream: &mut TcpStream) -> io::Result<()> {
    let mut until = Instant::now() + WRITE_TIMEOUT;
    while tls.wants_write() {
        match tls.write_tls(stream) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(_) => until = Instant::now() + WRITE_TIMEOUT,
            Err(error) => wait_for_room(error, until)?,
        }
    }
    Ok(())
}

/// Writes everything, waiting for room on a socket that does not block.
pub(crate) fn write_waiting(stream: &mut TcpStream, mut data: &[u8]) -> io::Result<()> {
    let mut until = Instant::now() + WRITE_TIMEOUT;
    while !data.is_empty() {
        match stream.write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                data = &data[count..];
                until = Instant::now() + WRITE_TIMEOUT;
            }
            Err(error) => wait_for_room(error, until)?,
        }
    }
    Ok(())
}

/// After a write failed: waits a moment when the socket is only full, up
/// to `until`, which a write that takes anything moves on: a slow reader is
/// waited for, one that takes nothing for 5 s is not. Any other error ends
/// the write.
fn wait_for_room(error: io::Error, until: Instant) -> io::Result<()> {
    match error.kind() {
        io::ErrorKind::WouldBlock => {
            if Instant::now() >= until {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the other end did not take what was sent for 5 s",
                ));
            }
            thread::sleep(Duration::from_millis(1));
            Ok(())
        }
        io::ErrorKind::Interrupted => Ok(()),
        _ => Err(error),
    }
}
