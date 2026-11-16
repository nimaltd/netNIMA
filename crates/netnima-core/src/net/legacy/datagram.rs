//! DTLS over OpenSSL, for old and small devices: DTLS 1.0, which dimpl does
//! not speak, and DTLS 1.2 with any suite OpenSSL has, the PSK, CBC and CCM
//! ones too.
//!
//! As with dimpl, the DTLS session owns the UDP socket. Each connection's
//! OpenSSL reads the datagrams the session gives it from one queue, and
//! writes the ones it sends to another, which the session empties. OpenSSL
//! is asked when its retransmission timer runs out, and moved on by hand
//! when it does.

use std::collections::VecDeque;
use std::ffi::{c_int, c_void};
use std::io::{self, Read, Write};
use std::ptr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{
    ErrorCode, Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslStream, SslVerifyMode,
    SslVersion,
};

use super::{
    agreed, client_trust, common, identity, names, psk_client, psk_server, server_identity, stack,
    use_identity, words,
};
use crate::net::dtls::{DtlsOptions, DtlsVersion, NOT_FINISHED};
use crate::net::tls::{Agreed, Verify};

/// DTLS_CTRL_GET_TIMEOUT and DTLS_CTRL_HANDLE_TIMEOUT in OpenSSL's ssl.h,
/// which its DTLSv1_get_timeout and DTLSv1_handle_timeout macros stand for.
const GET_TIMEOUT: c_int = 73;
const HANDLE_TIMEOUT: c_int = 74;

/// The largest datagram sent: one that crosses the internet without being
/// cut into IP fragments.
const MTU: u32 = 1200;

/// The most bytes of data a record can carry, as the other end may send.
const MOST_IN_RECORD: usize = 16384;

/// The bytes of data a record carries when OpenSSL cannot say yet: with any
/// suite's overhead, a datagram of 1 KB of data fits the MTU.
const RECORD_DATA: usize = 1024;

unsafe extern "C" {
    /// How many bytes of data a record takes for its datagram to fit the MTU,
    /// once the record's header and the suite's overhead are taken off; 0
    /// before a suite is agreed. OpenSSL has it since 1.1.1, and the openssl
    /// crate does not reach it.
    fn DTLS_get_data_mtu(ssl: *const openssl_sys::SSL) -> usize;
}

/// OpenSSL's struct timeval, as the platform has it.
#[cfg(windows)]
type TimeVal = windows_sys::Win32::Networking::WinSock::TIMEVAL;
#[cfg(unix)]
type TimeVal = libc::timeval;

/// The versions a tab speaks over OpenSSL, oldest first.
fn range(version: DtlsVersion) -> Result<(SslVersion, SslVersion), String> {
    match version {
        DtlsVersion::Auto | DtlsVersion::All => Ok((SslVersion::DTLS1, SslVersion::DTLS1_2)),
        DtlsVersion::Dtls10 => Ok((SslVersion::DTLS1, SslVersion::DTLS1)),
        DtlsVersion::Dtls12 => Ok((SslVersion::DTLS1_2, SslVersion::DTLS1_2)),
        DtlsVersion::Dtls13 => Err(
            "OpenSSL speaks DTLS 1.0 and 1.2 here: DTLS 1.3 is spoken by the Rust engine.".into(),
        ),
    }
}

/// What a DTLS tab makes its connections from, over OpenSSL.
pub(crate) struct DtlsSetup {
    context: SslContext,
    /// A client: whether the server's certificate is checked for its name.
    check_name: bool,
}

impl DtlsSetup {
    pub(crate) fn new(options: &DtlsOptions, client: bool) -> Result<Self, String> {
        let method = if client {
            SslMethod::dtls_client()
        } else {
            SslMethod::dtls_server()
        };
        let mut builder = SslContext::builder(method).map_err(stack("start"))?;
        // A server with a PSK still takes certificate clients: all suites stay on.
        common(
            &mut builder,
            range(options.version)?,
            &options.ciphers,
            client && options.psk,
            "",
        )?;
        // OpenSSL does not see the socket, so the size of datagrams is set,
        // not asked of it.
        builder.set_options(SslOptions::NO_QUERY_MTU);
        if client {
            client_trust(&mut builder, options.verify, &options.ca_file)?;
            if !options.cert_file.trim().is_empty() {
                let (chain, key) = identity(&options.cert_file, &options.key_file)?;
                use_identity(&mut builder, chain, &key)?;
            }
            if options.psk {
                psk_client(&mut builder, &options.psk_identity, &options.psk_key)?;
            }
        } else {
            server_identity(&mut builder, &options.cert_file, &options.key_file)?;
            if options.client_auth && !options.psk {
                // As with dimpl: a certificate is needed, and any is taken, to be seen.
                builder.set_verify_callback(
                    SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                    |_, _| true,
                );
            } else {
                builder.set_verify(SslVerifyMode::NONE);
            }
            if options.psk {
                psk_server(&mut builder, &options.psk_identity, &options.psk_key)?;
            }
            if options.cookie {
                cookies(&mut builder);
            }
        }
        Ok(Self {
            context: builder.build(),
            check_name: client
                && options.verify != Verify::None
                && options.check_name
                && !options.psk,
        })
    }

    /// A client's connection to the server known by `name`. Its first
    /// datagram is ready to go at once.
    pub(crate) fn connect(&self, name: &str, limit: Duration) -> Result<OldDtls, String> {
        let mut ssl = Ssl::new(&self.context).map_err(stack("make a connection"))?;
        names(&mut ssl, name, true, self.check_name)?;
        ssl.set_connect_state();
        let mut connection = OldDtls::new(ssl, limit)?;
        connection.pump()?;
        Ok(connection)
    }

    /// A server's connection to a client whose first datagram just came.
    pub(crate) fn accept(&self, limit: Duration) -> Result<OldDtls, String> {
        let mut ssl = Ssl::new(&self.context).map_err(stack("take a client"))?;
        ssl.set_accept_state();
        OldDtls::new(ssl, limit)
    }
}

/// The cookie a server gave a client, kept on that client's connection.
fn cookie_index() -> Index<Ssl, [u8; 16]> {
    static INDEX: OnceLock<Index<Ssl, [u8; 16]>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("OpenSSL gives an ex_data index"))
}

/// A server sends a cookie first (HelloVerifyRequest), and goes on with a
/// client only when it sends the cookie back.
fn cookies(builder: &mut SslContextBuilder) {
    builder.set_options(SslOptions::COOKIE_EXCHANGE);
    let index = cookie_index();
    builder.set_cookie_generate_cb(move |ssl, out| {
        let cookie = match ssl.ex_data(index).copied() {
            Some(cookie) => cookie,
            None => {
                let mut cookie = [0u8; 16];
                openssl::rand::rand_bytes(&mut cookie)?;
                ssl.set_ex_data(index, cookie);
                cookie
            }
        };
        let count = cookie.len().min(out.len());
        out[..count].copy_from_slice(&cookie[..count]);
        Ok(count)
    });
    builder.set_cookie_verify_cb(move |ssl, cookie| {
        ssl.ex_data(index)
            .is_some_and(|ours| ours.as_slice() == cookie)
    });
}

/// The two queues OpenSSL reads datagrams from and writes them to.
#[derive(Default)]
struct Datagrams {
    came: VecDeque<Vec<u8>>,
    going: Vec<Vec<u8>>,
}

impl Read for Datagrams {
    /// One whole datagram, or "try again later" when none waits.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(datagram) = self.came.pop_front() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let count = datagram.len().min(buf.len());
        buf[..count].copy_from_slice(&datagram[..count]);
        Ok(count)
    }
}

impl Write for Datagrams {
    /// Each write is one datagram.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.going.push(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What a connection did, for the session to tell.
pub(crate) enum Seen {
    Connected,
    Data(Vec<u8>),
    /// The other end said goodbye (close_notify).
    Closed,
}

/// One DTLS connection over OpenSSL.
pub(crate) struct OldDtls {
    stream: SslStream<Datagrams>,
    connected: bool,
    closed: bool,
    /// When it started, for the handshake's time limit.
    since: Instant,
    limit: Duration,
    seen: Vec<Seen>,
}

impl OldDtls {
    fn new(mut ssl: Ssl, limit: Duration) -> Result<Self, String> {
        ssl.set_mtu(MTU)
            .map_err(stack("set the size of datagrams"))?;
        let stream = SslStream::new(ssl, Datagrams::default()).map_err(stack("start"))?;
        Ok(Self {
            stream,
            connected: false,
            closed: false,
            since: Instant::now(),
            limit,
            seen: Vec::new(),
        })
    }

    /// Takes a datagram from the other end.
    pub(crate) fn handle_packet(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.stream.get_mut().came.push_back(bytes.to_vec());
        self.pump()
    }

    /// Moves the handshake on, then reads what came, as far as both go now.
    fn pump(&mut self) -> Result<(), String> {
        if self.closed {
            self.stream.get_mut().came.clear();
            return Ok(());
        }
        if !self.connected {
            match self.stream.do_handshake() {
                Ok(()) => {
                    self.connected = true;
                    self.seen.push(Seen::Connected);
                }
                Err(error) if waits(&error) => return Ok(()),
                Err(error) => return Err(self.problem(&error)),
            }
        }
        let mut buf = vec![0u8; MOST_IN_RECORD];
        loop {
            match self.stream.ssl_read(&mut buf) {
                Ok(count) => self.seen.push(Seen::Data(buf[..count].to_vec())),
                Err(error) if waits(&error) => return Ok(()),
                Err(error) if error.code() == ErrorCode::ZERO_RETURN => {
                    self.closed = true;
                    self.seen.push(Seen::Closed);
                    return Ok(());
                }
                Err(error) => return Err(self.problem(&error)),
            }
        }
    }

    /// What OpenSSL's timer was set for: a flight sent again, or a
    /// handshake that took too long.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        if !self.connected && now >= self.since + self.limit {
            return Err(NOT_FINISHED.into());
        }
        // SAFETY: the SSL is alive while `self` is, and this control takes
        // no argument. It does nothing when the timer has not run out.
        let handled = unsafe {
            openssl_sys::SSL_ctrl(
                self.stream.ssl().as_ptr(),
                HANDLE_TIMEOUT,
                0,
                ptr::null_mut(),
            )
        };
        if handled < 0 {
            let stack = ErrorStack::get();
            return Err(if self.connected {
                format!("The DTLS connection timed out (OpenSSL: {stack}).")
            } else {
                format!("{NOT_FINISHED} (OpenSSL: {stack})")
            });
        }
        Ok(())
    }

    /// When OpenSSL's timer runs out next, or the handshake's time does.
    pub(crate) fn next_timeout(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        // SAFETY: a struct timeval is plain numbers; zeros are one.
        let mut left: TimeVal = unsafe { std::mem::zeroed() };
        // SAFETY: the SSL is alive while `self` is, and this control writes
        // one struct timeval where it is pointed.
        let running = unsafe {
            openssl_sys::SSL_ctrl(
                self.stream.ssl().as_ptr(),
                GET_TIMEOUT,
                0,
                ptr::from_mut(&mut left).cast::<c_void>(),
            )
        } == 1;
        let timer = running.then(|| {
            Instant::now()
                + Duration::from_secs(u64::try_from(left.tv_sec).unwrap_or(0))
                + Duration::from_micros(u64::try_from(left.tv_usec).unwrap_or(0))
        });
        let deadline = (!self.connected).then(|| self.since + self.limit);
        timer.into_iter().chain(deadline).min()
    }

    /// Sends bytes, in as many records as it takes for each datagram to fit
    /// the MTU. OpenSSL puts what it is given at once in one record, up to
    /// 16 KB, which would cross the network as IP fragments, which small
    /// devices drop, and which macOS does not send at all above 9216 bytes.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        // SAFETY: the SSL is alive while `self` is, and this only reads it.
        let fits = unsafe { DTLS_get_data_mtu(self.stream.ssl().as_ptr()) };
        let most = if fits == 0 { RECORD_DATA } else { fits };
        for record in bytes.chunks(most) {
            if let Err(error) = self.stream.ssl_write(record) {
                return Err(self.problem(&error));
            }
        }
        Ok(())
    }

    /// Says goodbye (close_notify), when connected.
    pub(crate) fn close(&mut self) {
        if self.connected && !self.closed {
            let _ = self.stream.shutdown();
        }
        self.closed = true;
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    /// The datagrams to send now.
    pub(crate) fn take_datagrams(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.stream.get_mut().going)
    }

    /// What it did since it was last asked.
    pub(crate) fn take_seen(&mut self) -> Vec<Seen> {
        std::mem::take(&mut self.seen)
    }

    pub(crate) fn agreed(&self) -> Agreed {
        agreed(self.stream.ssl())
    }

    fn problem(&self, error: &openssl::ssl::Error) -> String {
        words(error, Some(self.stream.ssl()), "DTLS")
    }
}

/// Whether OpenSSL only waits for a datagram.
fn waits(error: &openssl::ssl::Error) -> bool {
    matches!(error.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE)
}
