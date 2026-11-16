//! FTP: a client that lists, gets and puts files on a device's FTP server,
//! and a server that serves a folder, to try a device's FTP client against.
//!
//! The control connection is the tab's socket. Each listing or file goes on
//! a data connection of its own, passive as firewalls like it, made on a
//! thread so the tab keeps going.
//!
//! With TLS on, it is FTPS (RFC 4217): explicit, where the connection starts
//! plain and AUTH TLS turns TLS on, or implicit, with TLS from the start, as
//! on port 990. PROT P puts each data connection in TLS too.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Engine, Io, SocketTls, TlsUse, Words};
use crate::net::secure::SecureStream;
use crate::net::tls::{self, ServerSetup};
use crate::net::{Peer, PeerId, Target, TlsClientOptions, TlsServerOptions};

/// How long a data connection waits to be made.
const DATA_WAIT: Duration = Duration::from_secs(10);

/// A data connection: plain, or in TLS after PROT P.
enum DataStream {
    Plain(TcpStream),
    Secure(Box<SecureStream>),
}

impl DataStream {
    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        let sent = match self {
            Self::Plain(stream) => stream.write_all(bytes),
            Self::Secure(stream) => stream.write_all(bytes).and_then(|()| stream.flush()),
        };
        sent.map_err(|error| error.to_string())
    }

    fn read_all(&mut self) -> Result<Vec<u8>, String> {
        let read = match self {
            Self::Plain(stream) => {
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).map(|_| bytes)
            }
            Self::Secure(stream) => stream.read_all(),
        };
        read.map_err(|error| error.to_string())
    }

    /// Ends it: TLS's goodbye first, so the other end knows all came, then
    /// the sending half, then what is left to read. On Windows, closing a
    /// socket with bytes unread, such as a TLS server's session tickets,
    /// resets the connection, and the other end loses what it has not read.
    fn finish(mut self) {
        let tcp = match &mut self {
            Self::Plain(stream) => &*stream,
            Self::Secure(stream) => {
                stream.finish();
                stream.tcp()
            }
        };
        let _ = tcp.shutdown(std::net::Shutdown::Write);
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(2)));
        let mut rest = [0u8; 4096];
        let mut tcp = tcp;
        while matches!(tcp.read(&mut rest), Ok(count) if count > 0) {}
    }
}

/// What a data connection did, told back to the tab.
enum Done {
    /// A transfer ended: what for, how many bytes, and why it failed, if it did.
    Transfer {
        peer: PeerId,
        what: String,
        bytes: usize,
        problem: Option<String>,
        listing: Option<String>,
        /// In TLS: whether it took up the control connection's session.
        resumed: Option<bool>,
    },
}

/// How a data connection went, in TLS or not, for the line that says it ended.
fn tls_words(resumed: Option<bool>) -> &'static str {
    match resumed {
        None => "",
        Some(true) => ", in TLS, its session taken up from the control connection",
        Some(false) => ", in TLS, with a session of its own",
    }
}

fn files_folder(folder: &str) -> PathBuf {
    if !folder.trim().is_empty() {
        return PathBuf::from(folder.trim());
    }
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join("Downloads")
}

/// A path the client named, inside the folder served, or None if it climbs out.
fn inside(root: &Path, current: &str, name: &str) -> Option<(PathBuf, String)> {
    let joined = if name.starts_with('/') {
        name.to_string()
    } else {
        format!("{}/{name}", current.trim_end_matches('/'))
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    let virtual_path = format!("/{}", parts.join("/"));
    Some((
        parts
            .iter()
            .fold(root.to_path_buf(), |path, part| path.join(part)),
        virtual_path,
    ))
}

/// A folder's listing as `ls -l` writes it, which FTP clients read.
fn listing(folder: &Path) -> Result<String, String> {
    let mut lines = Vec::new();
    let entries = std::fs::read_dir(folder).map_err(|error| error.to_string())?;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let modified: chrono::DateTime<chrono::Local> = meta
            .modified()
            .map_or_else(|_| chrono::Local::now(), chrono::DateTime::from);
        lines.push(format!(
            "{} 1 owner group {:>12} {} {}",
            if meta.is_dir() {
                "drwxr-xr-x"
            } else {
                "-rw-r--r--"
            },
            meta.len(),
            modified.format("%b %e %H:%M"),
            entry.file_name().to_string_lossy()
        ));
    }
    lines.sort();
    Ok(lines.iter().map(|line| format!("{line}\r\n")).collect())
}

/// One client's session on the server.
struct Session {
    buffer: Vec<u8>,
    user: String,
    logged_in: bool,
    current: String,
    /// The passive listener made for the next transfer.
    passive: Option<TcpListener>,
    rename_from: Option<PathBuf>,
    /// The control connection is in TLS.
    secure: bool,
    /// PROT P: data connections go in TLS.
    protect: bool,
}

/// An FTP server tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerOptions {
    /// The folder served: empty for Downloads.
    pub folder: String,
    /// The user and password clients must give; empty takes anyone.
    pub username: String,
    pub password: String,
    /// With TLS on: TLS from the start (implicit FTPS, as on port 990),
    /// rather than after AUTH TLS on a plain connection (explicit).
    pub implicit: bool,
}

/// Serves a folder over FTP.
pub struct Server {
    root: PathBuf,
    username: String,
    password: String,
    sessions: BTreeMap<PeerId, Session>,
    addresses: BTreeMap<PeerId, IpAddr>,
    done: (Sender<Done>, Receiver<Done>),
    implicit: bool,
    /// The tab's TLS, for data connections; none without TLS.
    data_tls: Option<ServerSetup>,
}

impl Server {
    pub fn new(options: ServerOptions) -> Self {
        Self {
            root: files_folder(&options.folder),
            username: options.username,
            password: options.password,
            sessions: BTreeMap::new(),
            addresses: BTreeMap::new(),
            done: mpsc::channel(),
            implicit: options.implicit,
            data_tls: None,
        }
    }

    fn reply(peer: PeerId, text: &str, io: &mut Io) {
        io.went(peer, text);
        io.send(Target::Peer(peer), format!("{text}\r\n").into_bytes());
    }

    /// The address a client reaches this PC at, for PASV: its own loopback,
    /// or an address of the PC on its network.
    fn own_address(&self, peer: PeerId) -> Ipv4Addr {
        let client = self.addresses.get(&peer).copied();
        if let Some(IpAddr::V4(client)) = client {
            if client.is_loopback() {
                return Ipv4Addr::LOCALHOST;
            }
            let found = crate::net::own_addresses();
            let same = found.iter().find_map(|ip| match ip {
                IpAddr::V4(ip) if ip.octets()[..3] == client.octets()[..3] => Some(*ip),
                _ => None,
            });
            if let Some(ip) = same {
                return ip;
            }
            if let Some(ip) = found.iter().find_map(|ip| match ip {
                IpAddr::V4(ip) if !ip.is_loopback() => Some(*ip),
                _ => None,
            }) {
                return ip;
            }
        }
        Ipv4Addr::LOCALHOST
    }

    /// Starts a transfer on the passive connection, on a thread.
    fn transfer(
        &mut self,
        peer: PeerId,
        what: String,
        send: Option<Vec<u8>>,
        save: Option<PathBuf>,
        io: &mut Io,
    ) {
        let Some(session) = self.sessions.get_mut(&peer) else {
            return;
        };
        let Some(listener) = session.passive.take() else {
            Self::reply(peer, "425 Use PASV or EPSV first.", io);
            return;
        };
        let secure = session.protect.then(|| self.data_tls.clone()).flatten();
        Self::reply(
            peer,
            if secure.is_some() {
                "150 Opening the data connection, in TLS."
            } else {
                "150 Opening the data connection."
            },
            io,
        );
        let sender = self.done.0.clone();
        let listing_text = send
            .as_ref()
            .filter(|_| what.starts_with("LIST") || what.starts_with("NLST"))
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        thread::spawn(move || {
            let result = (|| -> Result<usize, String> {
                let _ = listener.set_nonblocking(false);
                let (stream, _) = accept_within(&listener, DATA_WAIT)?;
                let mut stream = match &secure {
                    Some(setup) => {
                        DataStream::Secure(Box::new(SecureStream::server(stream, setup).map_err(
                            |error| format!("TLS on the data connection failed: {error}"),
                        )?))
                    }
                    None => DataStream::Plain(stream),
                };
                let moved = match (send, save) {
                    (Some(bytes), _) => {
                        stream.send(&bytes)?;
                        bytes.len()
                    }
                    (None, Some(path)) => {
                        let bytes = stream.read_all()?;
                        std::fs::write(&path, &bytes).map_err(|error| {
                            format!("could not save {}: {error}", path.display())
                        })?;
                        bytes.len()
                    }
                    (None, None) => 0,
                };
                stream.finish();
                Ok(moved)
            })();
            let (bytes, problem) = match result {
                Ok(bytes) => (bytes, None),
                Err(problem) => (0, Some(problem)),
            };
            let _ = sender.send(Done::Transfer {
                peer,
                what,
                bytes,
                problem,
                listing: listing_text,
                resumed: None,
            });
        });
    }

    fn handle(&mut self, peer: PeerId, line: &str, io: &mut Io) {
        let (verb, argument) = line
            .split_once(' ')
            .map_or((line, ""), |(verb, rest)| (verb, rest.trim()));
        let verb = verb.to_uppercase();
        let shown = if verb == "PASS" {
            "PASS ****".to_string()
        } else {
            line.to_string()
        };
        io.came(peer, &shown);
        let Some(session) = self.sessions.get_mut(&peer) else {
            return;
        };
        let open = self.username.is_empty() && self.password.is_empty();
        if !session.logged_in
            && !matches!(
                verb.as_str(),
                "USER" | "PASS" | "QUIT" | "FEAT" | "SYST" | "AUTH" | "PBSZ" | "PROT" | "OPTS"
            )
        {
            Self::reply(peer, "530 Log in first.", io);
            return;
        }
        let tls_here = self.data_tls.is_some();
        let current = session.current.clone();
        match verb.as_str() {
            "USER" => {
                session.user = argument.to_string();
                if open {
                    session.logged_in = true;
                    Self::reply(peer, "230 Logged in.", io);
                } else {
                    Self::reply(peer, "331 The password, please.", io);
                }
            }
            "PASS" => {
                if open || (session.user == self.username && argument == self.password) {
                    session.logged_in = true;
                    Self::reply(peer, "230 Logged in.", io);
                } else {
                    Self::reply(peer, "530 Wrong user name or password.", io);
                }
            }
            "SYST" => Self::reply(peer, "215 UNIX Type: L8", io),
            "FEAT" => Self::reply(
                peer,
                if tls_here {
                    "211-Features:\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n EPSV\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End"
                } else {
                    "211-Features:\r\n EPSV\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End"
                },
                io,
            ),
            "OPTS" => Self::reply(peer, "200 OK.", io),
            "AUTH" => {
                let asked = argument.to_uppercase();
                if !tls_here {
                    Self::reply(peer, "502 This server speaks FTP without TLS.", io);
                } else if session.secure {
                    Self::reply(peer, "503 TLS is on already.", io);
                } else if !matches!(asked.as_str(), "TLS" | "TLS-C" | "SSL") {
                    Self::reply(peer, "504 AUTH TLS is the one spoken here.", io);
                } else {
                    // The answer goes plain, and TLS starts right after it.
                    let text = "234 Go ahead with TLS.";
                    io.went(peer, text);
                    io.start_tls(peer, format!("{text}\r\n").into_bytes());
                    session.secure = true;
                }
            }
            "PBSZ" if !session.secure => Self::reply(peer, "503 AUTH TLS first.", io),
            "PBSZ" => Self::reply(peer, "200 PBSZ=0", io),
            "PROT" if !session.secure => Self::reply(peer, "503 AUTH TLS first.", io),
            "PROT" => match argument.to_uppercase().as_str() {
                "P" => {
                    session.protect = true;
                    Self::reply(peer, "200 Data connections go in TLS.", io);
                }
                "C" => {
                    session.protect = false;
                    Self::reply(peer, "200 Data connections go in the clear.", io);
                }
                _ => Self::reply(peer, "504 PROT P or PROT C.", io),
            },
            "NOOP" => Self::reply(peer, "200 OK.", io),
            "TYPE" | "MODE" | "STRU" => Self::reply(peer, "200 OK.", io),
            "PWD" | "XPWD" => Self::reply(peer, &format!("257 \"{current}\" is the folder."), io),
            "CWD" | "XCWD" | "CDUP" => {
                let target = if verb == "CDUP" { ".." } else { argument };
                match inside(&self.root, &current, target) {
                    Some((path, virtual_path)) if path.is_dir() => {
                        session.current = virtual_path;
                        Self::reply(peer, "250 OK.", io);
                    }
                    _ => Self::reply(peer, "550 No such folder.", io),
                }
            }
            "PASV" | "EPSV" => match TcpListener::bind(("0.0.0.0", 0)) {
                Ok(listener) => {
                    let port = listener.local_addr().map(|at| at.port()).unwrap_or(0);
                    session.passive = Some(listener);
                    if verb == "EPSV" {
                        Self::reply(
                            peer,
                            &format!("229 Entering Extended Passive Mode (|||{port}|)"),
                            io,
                        );
                    } else {
                        let ip = self.own_address(peer).octets();
                        Self::reply(
                            peer,
                            &format!(
                                "227 Entering Passive Mode ({},{},{},{},{},{})",
                                ip[0],
                                ip[1],
                                ip[2],
                                ip[3],
                                port >> 8,
                                port & 0xff
                            ),
                            io,
                        );
                    }
                }
                Err(error) => Self::reply(peer, &format!("425 No data port: {error}"), io),
            },
            "LIST" | "NLST" | "MLSD" => {
                let target = if argument.starts_with('-') {
                    ""
                } else {
                    argument
                };
                match inside(&self.root, &current, target).map(|(path, _)| path) {
                    Some(path) if path.is_dir() => match listing(&path) {
                        Ok(text) => {
                            let text = if verb == "NLST" {
                                text.lines()
                                    .filter_map(|line| line.rsplit(' ').next())
                                    .map(|name| format!("{name}\r\n"))
                                    .collect()
                            } else {
                                text
                            };
                            self.transfer(
                                peer,
                                format!("{verb} {current}"),
                                Some(text.into_bytes()),
                                None,
                                io,
                            );
                        }
                        Err(problem) => Self::reply(peer, &format!("550 {problem}"), io),
                    },
                    _ => Self::reply(peer, "550 No such folder.", io),
                }
            }
            "RETR" => match inside(&self.root, &current, argument).map(|(path, _)| path) {
                Some(path) if path.is_file() => match std::fs::read(&path) {
                    Ok(bytes) => {
                        self.transfer(peer, format!("RETR {argument}"), Some(bytes), None, io)
                    }
                    Err(error) => Self::reply(peer, &format!("550 {error}"), io),
                },
                _ => Self::reply(peer, "550 No such file.", io),
            },
            "STOR" => match inside(&self.root, &current, argument).map(|(path, _)| path) {
                Some(path) => self.transfer(peer, format!("STOR {argument}"), None, Some(path), io),
                None => Self::reply(peer, "553 Not a name a file can have here.", io),
            },
            "SIZE" => match inside(&self.root, &current, argument)
                .and_then(|(path, _)| std::fs::metadata(path).ok())
            {
                Some(meta) if meta.is_file() => {
                    Self::reply(peer, &format!("213 {}", meta.len()), io)
                }
                _ => Self::reply(peer, "550 No such file.", io),
            },
            "DELE" => match inside(&self.root, &current, argument)
                .map(|(path, _)| std::fs::remove_file(path))
            {
                Some(Ok(())) => Self::reply(peer, "250 Deleted.", io),
                _ => Self::reply(peer, "550 It could not be deleted.", io),
            },
            "MKD" | "XMKD" => match inside(&self.root, &current, argument) {
                Some((path, virtual_path)) if std::fs::create_dir(&path).is_ok() => {
                    Self::reply(peer, &format!("257 \"{virtual_path}\" made."), io)
                }
                _ => Self::reply(peer, "550 It could not be made.", io),
            },
            "RMD" | "XRMD" => match inside(&self.root, &current, argument)
                .map(|(path, _)| std::fs::remove_dir(path))
            {
                Some(Ok(())) => Self::reply(peer, "250 Removed.", io),
                _ => Self::reply(peer, "550 It could not be removed.", io),
            },
            "RNFR" => match inside(&self.root, &current, argument) {
                Some((path, _)) if path.exists() => {
                    session.rename_from = Some(path);
                    Self::reply(peer, "350 And the new name?", io);
                }
                _ => Self::reply(peer, "550 No such file.", io),
            },
            "RNTO" => match (
                session.rename_from.take(),
                inside(&self.root, &current, argument),
            ) {
                (Some(from), Some((to, _))) if std::fs::rename(&from, &to).is_ok() => {
                    Self::reply(peer, "250 Renamed.", io)
                }
                _ => Self::reply(peer, "550 It could not be renamed.", io),
            },
            "QUIT" => {
                Self::reply(peer, "221 Goodbye.", io);
                io.drop_peer(peer);
            }
            _ => Self::reply(peer, "502 Not done here.", io),
        }
    }
}

/// Accepts one connection, waiting up to `wait`.
fn accept_within(
    listener: &TcpListener,
    wait: Duration,
) -> Result<(TcpStream, SocketAddr), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let until = Instant::now() + wait;
    loop {
        match listener.accept() {
            Ok((stream, from)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                return Ok((stream, from));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err("the data connection was not made".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

impl Engine for Server {
    fn help(&self) -> &'static str {
        "It serves its folder: listings, files to get and put, folders made and removed.
folder      where that is"
    }

    fn joined(&mut self, peer: &Peer, io: &mut Io) {
        if let Ok(address) = peer.address.parse::<SocketAddr>() {
            self.addresses.insert(peer.id, address.ip());
        }
        self.sessions.insert(
            peer.id,
            Session {
                buffer: Vec::new(),
                user: String::new(),
                logged_in: false,
                current: "/".into(),
                passive: None,
                rename_from: None,
                secure: self.data_tls.is_some() && self.implicit,
                protect: false,
            },
        );
        Self::reply(
            peer.id,
            &format!("220 netNIMA FTP server {}", crate::VERSION),
            io,
        );
    }

    fn tls(&mut self, tls: Option<SocketTls>) -> TlsUse {
        let Some(SocketTls::Server(options)) = tls else {
            return TlsUse::default();
        };
        // The data connections share the control connection's sessions.
        let options = TlsServerOptions {
            share_sessions: true,
            ..options
        };
        // What is wrong with the settings, the socket says itself.
        self.data_tls = tls::server_setup(&options).ok();
        TlsUse {
            later: !self.implicit,
            shared: true,
        }
    }

    fn left(&mut self, peer: PeerId, _io: &mut Io) {
        self.sessions.remove(&peer);
        self.addresses.remove(&peer);
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let mut lines = Vec::new();
        if let Some(session) = self.sessions.get_mut(&peer) {
            session.buffer.extend_from_slice(bytes);
            while let Some(end) = session.buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = session.buffer.drain(..=end).collect();
                lines.push(String::from_utf8_lossy(&line).trim_end().to_string());
            }
        }
        for line in lines.into_iter().filter(|line| !line.is_empty()) {
            self.handle(peer, &line, io);
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "folder" => io.note(&format!("It serves {}.", self.root.display())),
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, _now: Instant, io: &mut Io) {
        while let Ok(Done::Transfer {
            peer,
            what,
            bytes,
            problem,
            ..
        }) = self.done.1.try_recv()
        {
            match problem {
                None => Self::reply(peer, &format!("226 {what}: {bytes} bytes."), io),
                Some(problem) => Self::reply(peer, &format!("426 {what} failed: {problem}"), io),
            }
        }
    }
}

// ----- The client -----

/// An FTP client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    pub username: String,
    pub password: String,
    /// The folder files are got into and put from: empty for Downloads.
    pub folder: String,
    /// The host the tab connects to, where data connections go.
    pub host: String,
    /// With TLS on: TLS from the start (implicit FTPS, as on port 990),
    /// rather than AUTH TLS on a plain connection (explicit).
    pub implicit: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            username: "anonymous".into(),
            password: "netnima@".into(),
            folder: String::new(),
            host: "localhost".into(),
            implicit: false,
        }
    }
}

/// What the client does once the server says where to connect for data.
enum Next {
    List(String),
    Get(String),
    Put(String, Vec<u8>),
}

/// Where the client is in logging in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Greeting,
    /// AUTH TLS sent.
    Auth,
    /// PBSZ 0 sent.
    Pbsz,
    /// PROT P sent.
    Prot,
    /// USER sent, or what comes after.
    Login,
}

/// Talks to an FTP server: logs in, lists, gets and puts.
pub struct Client {
    options: ClientOptions,
    folder: PathBuf,
    peer: Option<PeerId>,
    buffer: Vec<u8>,
    next: Option<Next>,
    done: (Sender<Done>, Receiver<Done>),
    /// The tab's TLS, for data connections; none without TLS.
    data_tls: Option<TlsClientOptions>,
    stage: Stage,
    /// The control connection is in TLS.
    secure: bool,
    /// PROT P was taken: data connections go in TLS.
    protect: bool,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        Self {
            folder: files_folder(&options.folder),
            options,
            peer: None,
            buffer: Vec::new(),
            next: None,
            done: mpsc::channel(),
            data_tls: None,
            stage: Stage::Greeting,
            secure: false,
            protect: false,
        }
    }

    fn log_in(&mut self, io: &mut Io) {
        self.stage = Stage::Login;
        let user = format!("USER {}", self.options.username);
        self.send(&user, io);
    }

    fn send(&mut self, line: &str, io: &mut Io) {
        let Some(peer) = self.peer else {
            io.bad("Not connected: nothing was sent.");
            return;
        };
        let shown = if line.starts_with("PASS ") {
            "PASS ****"
        } else {
            line
        };
        io.went(peer, shown);
        io.send(Target::Default, format!("{line}\r\n").into_bytes());
    }

    /// Connects for data where the server said, and does what waits.
    fn data(&mut self, address: SocketAddr, io: &mut Io) {
        let Some(next) = self.next.take() else {
            return;
        };
        let peer = self.peer.unwrap_or(0);
        let (command, what) = match &next {
            Next::List(path) => (
                format!("LIST {path}").trim().to_string(),
                "listing".to_string(),
            ),
            Next::Get(name) => (format!("RETR {name}"), name.clone()),
            Next::Put(name, _) => (format!("STOR {name}"), name.clone()),
        };
        let folder = self.folder.clone();
        let sender = self.done.0.clone();
        // TLS on the data connection, with the control connection's settings,
        // so its session is taken up again where the server wants that.
        let secure = self
            .data_tls
            .clone()
            .filter(|_| self.protect)
            .map(|options| (options, self.options.host.clone()));
        thread::spawn(move || {
            let mut resumed = None;
            let result = (|| -> Result<(usize, Option<String>), String> {
                let stream = TcpStream::connect_timeout(&address, DATA_WAIT)
                    .map_err(|error| error.to_string())?;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let mut stream = match secure {
                    Some((options, host)) => {
                        let setup = tls::client_setup(&options, &host)?;
                        let stream = SecureStream::client(stream, setup).map_err(|error| {
                            format!("TLS on the data connection failed: {error}")
                        })?;
                        resumed = Some(stream.resumed());
                        DataStream::Secure(Box::new(stream))
                    }
                    None => DataStream::Plain(stream),
                };
                let moved = match next {
                    Next::List(_) => {
                        let bytes = stream.read_all()?;
                        (
                            bytes.len(),
                            Some(String::from_utf8_lossy(&bytes).into_owned()),
                        )
                    }
                    Next::Get(name) => {
                        let bytes = stream.read_all()?;
                        let file = folder.join(Path::new(&name).file_name().unwrap_or_default());
                        std::fs::write(&file, &bytes).map_err(|error| {
                            format!("could not save {}: {error}", file.display())
                        })?;
                        (bytes.len(), Some(format!("saved to {}", file.display())))
                    }
                    Next::Put(_, bytes) => {
                        stream.send(&bytes)?;
                        (bytes.len(), None)
                    }
                };
                stream.finish();
                Ok(moved)
            })();
            let done = match result {
                Ok((bytes, listing)) => Done::Transfer {
                    peer,
                    what,
                    bytes,
                    problem: None,
                    listing,
                    resumed,
                },
                Err(problem) => Done::Transfer {
                    peer,
                    what,
                    bytes: 0,
                    problem: Some(problem),
                    listing: None,
                    resumed,
                },
            };
            let _ = sender.send(done);
        });
        // The command goes once the thread connects: the server waits for both.
        self.send(&command, io);
    }

    fn reply(&mut self, peer: PeerId, line: &str, io: &mut Io) {
        io.came(peer, line);
        let code = line.get(..3).unwrap_or("");
        // A line of a reply with more to come.
        if line.as_bytes().get(3) == Some(&b'-') {
            return;
        }
        match (code, self.stage) {
            ("220", Stage::Greeting) => match (self.data_tls.is_some(), self.secure) {
                (true, false) => {
                    self.stage = Stage::Auth;
                    self.send("AUTH TLS", io);
                }
                (true, true) => {
                    self.stage = Stage::Pbsz;
                    self.send("PBSZ 0", io);
                }
                (false, _) => self.log_in(io),
            },
            ("234", Stage::Auth) => {
                io.start_tls(peer, Vec::new());
                self.secure = true;
                self.stage = Stage::Pbsz;
                self.send("PBSZ 0", io);
            }
            ("200", Stage::Pbsz) => {
                self.stage = Stage::Prot;
                self.send("PROT P", io);
            }
            ("200", Stage::Prot) => {
                self.protect = true;
                self.log_in(io);
            }
            (_, Stage::Auth) => {
                io.bad("The server turned AUTH TLS down: it does not log in, so the password does not go in the clear. Turn TLS off to use FTP as it is.");
            }
            (_, Stage::Pbsz | Stage::Prot) => {
                io.bad("The server keeps data connections in the clear: only the control connection is in TLS.");
                self.log_in(io);
            }
            _ => self.answer(code, line, io),
        }
    }

    /// A reply after logging in has begun.
    fn answer(&mut self, code: &str, line: &str, io: &mut Io) {
        match code {
            "331" => {
                let pass = format!("PASS {}", self.options.password);
                self.send(&pass, io);
            }
            "230" => io.note("Logged in. Type ls, get <file>, put <file>, cd <folder>."),
            "227" => {
                // (h1,h2,h3,h4,p1,p2)
                let numbers: Vec<u16> = line
                    .split(['(', ')'])
                    .nth(1)
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|part| part.trim().parse().ok())
                    .collect();
                if numbers.len() == 6 {
                    let mut ip = Ipv4Addr::new(
                        numbers[0] as u8,
                        numbers[1] as u8,
                        numbers[2] as u8,
                        numbers[3] as u8,
                    );
                    // A server behind NAT names an address the PC cannot reach: the host is used then.
                    if let Ok(host) = self.options.host.parse::<Ipv4Addr>()
                        && (ip.is_private() != host.is_private() || ip.is_unspecified())
                    {
                        ip = host;
                    }
                    self.data(SocketAddr::from((ip, numbers[4] << 8 | numbers[5])), io);
                }
            }
            "229" => {
                let port: Option<u16> = line.split('|').nth(3).and_then(|port| port.parse().ok());
                let host = super::super::net::host_and_port(&self.options.host, port.unwrap_or(0));
                match (
                    port,
                    host.parse::<SocketAddr>().ok().or_else(|| {
                        std::net::ToSocketAddrs::to_socket_addrs(&host)
                            .ok()
                            .and_then(|mut found| found.next())
                    }),
                ) {
                    (Some(_), Some(address)) => self.data(address, io),
                    _ => io.bad("The server's EPSV answer cannot be read."),
                }
            }
            _ => {}
        }
    }
}

impl Engine for Client {
    fn help(&self) -> &'static str {
        "ls [folder]        list
cd <folder>        change folder
pwd                where it is
get <file>         get a file into the tab's folder
put <file>         put a file of the tab's folder
delete <file>      delete a file
mkdir <folder>     make a folder
quote <command>    any FTP command, such as quote SYST"
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        self.peer = Some(peer.id);
        self.buffer.clear();
        self.stage = Stage::Greeting;
        self.secure = self.data_tls.is_some() && self.options.implicit;
        self.protect = false;
    }

    fn left(&mut self, _peer: PeerId, _io: &mut Io) {
        self.peer = None;
    }

    fn tls(&mut self, tls: Option<SocketTls>) -> TlsUse {
        let Some(SocketTls::Client(options)) = tls else {
            return TlsUse::default();
        };
        // The data connections take up the control connection's session.
        self.data_tls = Some(TlsClientOptions {
            share_sessions: true,
            ..options
        });
        TlsUse {
            later: !self.options.implicit,
            shared: true,
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.buffer.extend_from_slice(bytes);
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line).trim_end().to_string();
            if !line.is_empty() {
                self.reply(peer, &line, io);
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            let command = words.next().unwrap_or_default().to_lowercase();
            match command.as_str() {
                "ls" | "dir" | "list" => {
                    self.next = Some(Next::List(words.rest_text()));
                    self.send("PASV", io);
                }
                "get" => {
                    self.next = Some(Next::Get(words.need("the file's name")?));
                    self.send("TYPE I", io);
                    self.send("PASV", io);
                }
                "put" => {
                    let name = words.need("the file's name")?;
                    let path = self.folder.join(&name);
                    let bytes = std::fs::read(&path)
                        .map_err(|error| format!("Could not read {}: {error}", path.display()))?;
                    let remote = Path::new(&name)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or(name);
                    self.next = Some(Next::Put(remote, bytes));
                    self.send("TYPE I", io);
                    self.send("PASV", io);
                }
                "cd" => {
                    let folder = words.need("the folder")?;
                    self.send(&format!("CWD {folder}"), io);
                }
                "pwd" => self.send("PWD", io),
                "delete" | "rm" => {
                    let name = words.need("the file")?;
                    self.send(&format!("DELE {name}"), io);
                }
                "mkdir" => {
                    let name = words.need("the folder")?;
                    self.send(&format!("MKD {name}"), io);
                }
                "quote" | "raw" => {
                    let line = words.rest_text();
                    self.send(&line, io);
                }
                "quit" | "bye" => self.send("QUIT", io),
                other => {
                    return Err(format!(
                        "{other} is not a command here. Type help for the list."
                    ));
                }
            }
            Ok(())
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }

    fn tick(&mut self, _now: Instant, io: &mut Io) {
        while let Ok(Done::Transfer {
            what,
            bytes,
            problem,
            listing,
            resumed,
            ..
        }) = self.done.1.try_recv()
        {
            let secure = tls_words(resumed);
            match problem {
                None => {
                    if what == "listing" {
                        io.note(listing.unwrap_or_default().trim_end());
                        if !secure.is_empty() {
                            io.note(&format!("The listing came{secure}."));
                        }
                    } else {
                        let saved = listing.map(|text| format!(", {text}")).unwrap_or_default();
                        io.note(&format!("{what}: {bytes} bytes{saved}{secure}."));
                    }
                }
                Some(problem) => io.bad(&format!("{what}: {problem}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{client_to, listening, server_on_loopback, shown, start};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn paths_stay_inside_the_folder() {
        let root = Path::new("/srv");
        assert_eq!(inside(root, "/", "a/b.txt").unwrap().1, "/a/b.txt");
        assert_eq!(inside(root, "/a", "../c").unwrap().1, "/c");
        assert!(inside(root, "/", "../etc/passwd").is_none());
    }

    #[test]
    fn a_client_lists_gets_and_puts_on_the_server() {
        let folder = crate::certs::tests::scratch("ftp");
        let served = folder.join("served");
        let local = folder.join("local");
        std::fs::create_dir_all(&served).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(served.join("log.txt"), b"boot ok\n").unwrap();
        std::fs::write(local.join("config.json"), br#"{"rate":10}"#).unwrap();
        let (_server, server_events) = start(
            Box::new(Server::new(ServerOptions {
                folder: served.display().to_string(),
                username: "board".into(),
                password: "secret".into(),
                implicit: false,
            })),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                username: "board".into(),
                password: "secret".into(),
                folder: local.display().to_string(),
                host: "127.0.0.1".into(),
                implicit: false,
            })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        shown(&client_events, "230 Logged in.");
        client.command("ls");
        shown(&client_events, "log.txt");
        client.command("get log.txt");
        shown(&client_events, "log.txt: 8 bytes");
        assert_eq!(std::fs::read(local.join("log.txt")).unwrap(), b"boot ok\n");
        client.command("put config.json");
        shown(&client_events, "config.json: 11 bytes.");
        // The server says so once the file is saved.
        shown(&server_events, "226 STOR config.json: 11 bytes.");
        assert_eq!(
            std::fs::read(served.join("config.json")).unwrap(),
            br#"{"rate":10}"#
        );
        let _ = std::fs::remove_dir_all(folder);
    }

    #[test]
    fn ftps_explicit_and_implicit_list_get_and_put_in_tls() {
        use crate::net::{TlsServerOptions, Verify};
        for implicit in [false, true] {
            let folder =
                crate::certs::tests::scratch(if implicit { "ftps-990" } else { "ftps-21" });
            let served = folder.join("served");
            let local = folder.join("local");
            std::fs::create_dir_all(&served).unwrap();
            std::fs::create_dir_all(&local).unwrap();
            std::fs::write(served.join("log.txt"), b"boot ok\n").unwrap();
            std::fs::write(local.join("config.json"), br#"{"rate":10}"#).unwrap();
            let (_server, server_events) = start(
                Box::new(Server::new(ServerOptions {
                    folder: served.display().to_string(),
                    username: "board".into(),
                    password: "secret".into(),
                    implicit,
                })),
                SocketKind::Server,
                SocketSetup {
                    server: Some(crate::net::TcpServerConfig {
                        tls: Some(TlsServerOptions::default()),
                        ..server_on_loopback()
                    }),
                    ..SocketSetup::default()
                },
            );
            let port = listening(&server_events);
            let (client, client_events) = start(
                Box::new(Client::new(ClientOptions {
                    username: "board".into(),
                    password: "secret".into(),
                    folder: local.display().to_string(),
                    host: "127.0.0.1".into(),
                    implicit,
                })),
                SocketKind::Client,
                SocketSetup {
                    client: Some(crate::net::TcpClientConfig {
                        tls: Some(TlsClientOptions {
                            verify: Verify::None,
                            ..TlsClientOptions::default()
                        }),
                        ..client_to(port)
                    }),
                    ..SocketSetup::default()
                },
            );
            let text = shown(&client_events, "230 Logged in.");
            assert_eq!(text.contains("234 Go ahead with TLS."), !implicit, "{text}");
            assert!(text.contains("200 Data connections go in TLS."), "{text}");
            client.command("ls");
            shown(
                &client_events,
                "The listing came, in TLS, its session taken up from the control connection.",
            );
            shown(&server_events, "150 Opening the data connection, in TLS.");
            client.command("get log.txt");
            let text = shown(
                &client_events,
                "in TLS, its session taken up from the control connection.",
            );
            assert!(text.contains("log.txt: 8 bytes, saved to"), "{text}");
            assert_eq!(std::fs::read(local.join("log.txt")).unwrap(), b"boot ok\n");
            client.command("put config.json");
            shown(&server_events, "226 STOR config.json: 11 bytes.");
            assert_eq!(
                std::fs::read(served.join("config.json")).unwrap(),
                br#"{"rate":10}"#
            );
            let _ = std::fs::remove_dir_all(folder);
        }
    }
}
