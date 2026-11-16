//! HTTP/1.1: a client for a device's web API, and a server with routes made
//! by hand, so each end can be tried against the other, plain or over TLS.
//!
//! Messages are read off the stream whole, with their bodies by
//! Content-Length or in chunks, and shown with their headers and body.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use super::{Engine, Io, Words, hex, payload_text};
use crate::net::{Peer, PeerId, Target};

/// A message's status from its first line, "HTTP/1.1 200 OK": 0 when it has none.
fn status_of(start: &str) -> u16 {
    start
        .split(' ')
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or(0)
}

/// The most a message may be: more is taken as a broken stream.
const MOST: usize = 16 * 1024 * 1024;
/// The most of a body shown.
const SHOWN: usize = 2000;

/// An HTTP message: a request or a response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// "GET /a HTTP/1.1" or "HTTP/1.1 200 OK".
    pub start: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Message {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(found, _)| found.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("{}\r\n", self.start).into_bytes();
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// The first line, the headers indented under it, and the body.
    pub fn describe(&self) -> String {
        let mut text = self.start.clone();
        let size = self.body.len();
        if size > 0 {
            text.push_str(&format!(", {size} bytes"));
        }
        for (name, value) in &self.headers {
            text.push_str(&format!("\n{name}: {value}"));
        }
        if !self.body.is_empty() {
            let shown = &self.body[..size.min(SHOWN)];
            let body = match std::str::from_utf8(shown) {
                Ok(text) => text.replace('\r', ""),
                Err(_) => payload_text(shown),
            };
            text.push('\n');
            text.push_str(&body);
            if size > SHOWN {
                text.push_str(&format!("\n... ({} bytes more)", size - SHOWN));
            }
        }
        text
    }
}

/// How the body of a message being read is to be found.
enum Body {
    Length(usize),
    Chunked,
    /// A response that ends when the connection does.
    UntilClose,
    None,
}

/// Takes the first whole message off a stream's bytes. A response to HEAD,
/// or with a status that has none, has no body: `no_body` says so.
pub fn take(buffer: &mut Vec<u8>, no_body: bool, closed: bool) -> Result<Option<Message>, String> {
    let Some(end) = find(buffer, b"\r\n\r\n") else {
        if buffer.len() > 64 * 1024 {
            return Err("its headers are longer than 64 KB: is this HTTP?".into());
        }
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let start = lines.next().unwrap_or_default().to_string();
    if !(start.starts_with("HTTP/")
        || start
            .split(' ')
            .nth(2)
            .is_some_and(|version| version.starts_with("HTTP/")))
    {
        return Err(format!("{start:?} does not start an HTTP message"));
    }
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    let mut message = Message {
        start,
        headers,
        body: Vec::new(),
    };
    let is_response = message.start.starts_with("HTTP/");
    let status: u16 = message
        .start
        .split(' ')
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or(0);
    let body = if no_body || (is_response && (status / 100 == 1 || status == 204 || status == 304))
    {
        Body::None
    } else if message
        .header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        Body::Chunked
    } else if let Some(length) = message.header("content-length") {
        Body::Length(
            length
                .parse()
                .map_err(|_| format!("Content-Length is {length:?}"))?,
        )
    } else if is_response {
        Body::UntilClose
    } else {
        Body::None
    };
    let rest = &buffer[end + 4..];
    let used = match body {
        Body::None => 0,
        Body::Length(length) => {
            if length > MOST {
                return Err(format!(
                    "a body of {length} bytes is more than netNIMA takes"
                ));
            }
            if rest.len() < length {
                return Ok(None);
            }
            message.body = rest[..length].to_vec();
            length
        }
        Body::Chunked => match chunks(rest)? {
            Some((body, used)) => {
                message.body = body;
                used
            }
            None => return Ok(None),
        },
        Body::UntilClose => {
            if !closed {
                return Ok(None);
            }
            message.body = rest.to_vec();
            rest.len()
        }
    };
    buffer.drain(..end + 4 + used);
    Ok(Some(message))
}

/// A chunked body, whole, and how many bytes it took; None while it is not all there.
fn chunks(bytes: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    let mut body = Vec::new();
    let mut at = 0;
    loop {
        let Some(line_end) = find(&bytes[at..], b"\r\n") else {
            return Ok(None);
        };
        let size_text = String::from_utf8_lossy(&bytes[at..at + line_end]).into_owned();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| format!("a chunk's size is {size_text:?}"))?;
        at += line_end + 2;
        if size == 0 {
            // Trailers, then the empty line.
            let Some(trailer_end) = find(&bytes[at..], b"\r\n") else {
                return Ok(None);
            };
            if trailer_end == 0 {
                return Ok(Some((body, at + 2)));
            }
            let Some(all_end) = find(&bytes[at..], b"\r\n\r\n") else {
                return Ok(None);
            };
            return Ok(Some((body, at + all_end + 4)));
        }
        if bytes.len() < at + size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&bytes[at..at + size]);
        at += size + 2;
        if body.len() > MOST {
            return Err("a chunked body is more than netNIMA takes".into());
        }
    }
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The usual words for a status code.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// The content type of a body typed in: JSON when it looks like JSON.
fn guess_type(body: &[u8]) -> &'static str {
    match body.iter().find(|byte| !byte.is_ascii_whitespace()) {
        Some(b'{') | Some(b'[') => "application/json",
        Some(b'<') => "text/html; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    }
}

// ----- The client -----

/// An HTTP client tab's settings. The host and port come from the tab's connection.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// The host the tab connects to, for the Host header.
    pub host: String,
    pub port: u16,
    /// Headers every request has, as "Name: value" with semicolons between,
    /// such as "Authorization: Bearer abc; Accept: application/json".
    pub headers: String,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 80,
            headers: String::new(),
        }
    }
}

pub struct Client {
    host: String,
    headers: Vec<(String, String)>,
    peer: Option<PeerId>,
    buffer: Vec<u8>,
    /// The methods of requests sent and not answered, in order: a response
    /// to HEAD has no body.
    asked: Vec<(String, Instant)>,
    /// Whether the headers every request has changed since the view was told.
    headers_changed: bool,
}

fn parse_headers(text: &str) -> Vec<(String, String)> {
    text.split(';')
        .filter_map(|pair| pair.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let host = if options.port == 80 || options.port == 443 || options.port == 0 {
            options.host.trim().to_string()
        } else {
            super::super::net::host_and_port(&options.host, options.port)
        };
        Self {
            host,
            headers: parse_headers(&options.headers),
            peer: None,
            buffer: Vec::new(),
            asked: Vec::new(),
            headers_changed: true,
        }
    }

    fn read_responses(&mut self, peer: PeerId, closed: bool, io: &mut Io) {
        loop {
            let head = self
                .asked
                .first()
                .is_some_and(|(method, _)| method == "HEAD");
            match take(&mut self.buffer, head, closed) {
                Ok(Some(message)) => {
                    let (took, ms) = if self.asked.is_empty() {
                        (String::new(), None)
                    } else {
                        let (_, sent) = self.asked.remove(0);
                        let ms = sent.elapsed().as_secs_f64() * 1000.0;
                        (format!(" ({} ms)", ms.round()), Some(ms))
                    };
                    let headers: Vec<[&str; 2]> = message
                        .headers
                        .iter()
                        .map(|(name, value)| [name.as_str(), value.as_str()])
                        .collect();
                    io.report(json!({
                        "type": "response",
                        "status": status_of(&message.start),
                        "start": message.start,
                        "headers": headers,
                        "body": hex(&message.body),
                        "ms": ms,
                    }));
                    let text = message.describe();
                    let (first, rest) = text.split_once('\n').unwrap_or((&text, ""));
                    let shown = if rest.is_empty() {
                        format!("{first}{took}")
                    } else {
                        format!("{first}{took}\n{rest}")
                    };
                    io.came(peer, &shown);
                }
                Ok(None) => break,
                Err(problem) => {
                    io.bad(&format!("What came is not HTTP: {problem}."));
                    self.buffer.clear();
                    break;
                }
            }
        }
    }
}

const CLIENT_HELP: &str = "get <path>                  GET, such as get /api/status
head <path>                 HEAD
delete <path>               DELETE
post <path> <body>          POST; a body that starts with { or [ goes as JSON
put <path> <body>           PUT
patch <path> <body>         PATCH
header <Name>: <value>      a header for every request after; header <Name>: to drop it
headers                     the headers every request has";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        self.peer = Some(peer.id);
        self.buffer.clear();
        self.asked.clear();
    }

    fn left(&mut self, peer: PeerId, io: &mut Io) {
        // A response that ends with the connection is whole now.
        self.read_responses(peer, true, io);
        self.peer = None;
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.buffer.extend_from_slice(bytes);
        self.read_responses(peer, false, io);
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let command = words.next().unwrap_or_default();
        let method = command.to_uppercase();
        let result = (|| -> Result<(), String> {
            match method.as_str() {
                "GET" | "HEAD" | "DELETE" | "OPTIONS" | "POST" | "PUT" | "PATCH" => {
                    let path = words.need("the path, such as /api/status")?;
                    let path = if path.starts_with('/') || path.starts_with("http") {
                        path
                    } else {
                        format!("/{path}")
                    };
                    let body = words.rest();
                    let mut headers = vec![("Host".to_string(), self.host.clone())];
                    headers.push(("User-Agent".into(), format!("netNIMA/{}", crate::VERSION)));
                    let ours: Vec<String> = self
                        .headers
                        .iter()
                        .map(|(name, _)| name.to_lowercase())
                        .collect();
                    if !ours.contains(&"accept".to_string()) {
                        headers.push(("Accept".into(), "*/*".into()));
                    }
                    headers.extend(self.headers.iter().cloned());
                    if !body.is_empty() || matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
                        if !ours.contains(&"content-type".to_string()) {
                            headers.push(("Content-Type".into(), guess_type(&body).into()));
                        }
                        headers.push(("Content-Length".into(), body.len().to_string()));
                    }
                    let message = Message {
                        start: format!("{method} {path} HTTP/1.1"),
                        headers,
                        body,
                    };
                    let Some(peer) = self.peer else {
                        return Err("Not connected: nothing was sent.".into());
                    };
                    io.report(json!({ "type": "request", "method": method, "path": path }));
                    io.went(peer, &message.describe());
                    io.send(Target::Default, message.encode());
                    self.asked.push((method.clone(), Instant::now()));
                    Ok(())
                }
                "HEADER" => {
                    let text = words.rest_text();
                    let (name, value) = text
                        .split_once(':')
                        .ok_or("Write the header as Name: value.")?;
                    let name = name.trim().to_string();
                    self.headers_changed = true;
                    self.headers
                        .retain(|(known, _)| !known.eq_ignore_ascii_case(&name));
                    if value.trim().is_empty() {
                        io.note(&format!("{name} is not sent any more."));
                    } else {
                        self.headers.push((name.clone(), value.trim().to_string()));
                        io.note(&format!("Every request has {name} now."));
                    }
                    Ok(())
                }
                "HEADERS" => {
                    if self.headers.is_empty() {
                        io.note("Only the usual headers: Host, User-Agent, Accept.");
                    }
                    let lines: Vec<String> = self
                        .headers
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect();
                    for line in lines {
                        io.note(&line);
                    }
                    Ok(())
                }
                _ => Err(format!(
                    "{command} is not a command here. Type help for the list."
                )),
            }
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        if let Some((method, sent)) = self.asked.first()
            && now.duration_since(*sent) > Duration::from_secs(30)
        {
            io.bad(&format!("No answer to {method} in 30 s."));
            io.report(json!({ "type": "timeout", "method": method }));
            self.asked.remove(0);
        }
        if self.headers_changed {
            self.headers_changed = false;
            let headers: Vec<[&str; 2]> = self
                .headers
                .iter()
                .map(|(name, value)| [name.as_str(), value.as_str()])
                .collect();
            io.report(json!({ "type": "headers", "headers": headers }));
        }
    }
}

// ----- The server -----

/// An HTTP server tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerOptions {
    /// A folder whose files it serves, for paths no route has; empty for none.
    pub folder: String,
}

struct Route {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

pub struct Server {
    folder: String,
    /// By method and path, such as ("GET", "/api/status").
    routes: BTreeMap<(String, String), Route>,
    buffers: BTreeMap<PeerId, Vec<u8>>,
    /// Whether the routes changed since the view was told.
    routes_changed: bool,
}

impl Server {
    pub fn new(options: ServerOptions) -> Self {
        let mut routes = BTreeMap::new();
        routes.insert(
            ("GET".to_string(), "/api/status".to_string()),
            Route {
                status: 200,
                content_type: "application/json".into(),
                body: br#"{"ok":true,"from":"netNIMA"}"#.to_vec(),
            },
        );
        Self {
            folder: options.folder.trim().to_string(),
            routes,
            buffers: BTreeMap::new(),
            routes_changed: true,
        }
    }

    fn page(&self) -> Vec<u8> {
        let mut html = String::from(
            "<!doctype html><meta charset=utf-8><title>netNIMA</title><h1>netNIMA HTTP server</h1><p>Its routes:</p><ul>",
        );
        for (method, path) in self.routes.keys() {
            html.push_str(&format!("<li>{method} <a href=\"{path}\">{path}</a></li>"));
        }
        html.push_str("</ul>");
        html.into_bytes()
    }

    fn respond(&self, request: &Message) -> Message {
        let mut parts = request.start.split(' ');
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("/");
        let path = target.split('?').next().unwrap_or("/").to_string();
        let (status, content_type, body) =
            if let Some(route) = self.routes.get(&(method.clone(), path.clone())) {
                (route.status, route.content_type.clone(), route.body.clone())
            } else if method == "GET" && path == "/" {
                (200, "text/html; charset=utf-8".into(), self.page())
            } else if let Some(file) = self
                .file(&path)
                .filter(|_| method == "GET" || method == "HEAD")
            {
                (200, file_type(&path).into(), file)
            } else if method == "POST" && path == "/echo" {
                (
                    200,
                    request
                        .header("content-type")
                        .unwrap_or("text/plain")
                        .to_string(),
                    request.body.clone(),
                )
            } else if self.routes.keys().any(|(_, known)| *known == path) {
                (
                    405,
                    "text/plain; charset=utf-8".into(),
                    format!("{method} is not taken at {path}.\n").into_bytes(),
                )
            } else {
                (
                    404,
                    "text/plain; charset=utf-8".into(),
                    format!("Nothing at {path}.\n").into_bytes(),
                )
            };
        let mut headers = vec![
            ("Server".to_string(), format!("netNIMA/{}", crate::VERSION)),
            ("Content-Type".into(), content_type),
            ("Content-Length".into(), body.len().to_string()),
        ];
        if request
            .header("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close"))
        {
            headers.push(("Connection".into(), "close".into()));
        }
        Message {
            start: format!("HTTP/1.1 {status} {}", reason(status)),
            headers,
            body: if method == "HEAD" { Vec::new() } else { body },
        }
    }

    /// A file of the folder served, if the path names one inside it.
    fn file(&self, path: &str) -> Option<Vec<u8>> {
        if self.folder.is_empty() || path.contains("..") {
            return None;
        }
        let relative = path.trim_start_matches('/');
        let relative = if relative.is_empty() {
            "index.html"
        } else {
            relative
        };
        std::fs::read(std::path::Path::new(&self.folder).join(relative)).ok()
    }
}

fn file_type(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "json" => "application/json",
        "js" => "text/javascript",
        "css" => "text/css",
        "txt" | "log" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

const SERVER_HELP: &str = "route <METHOD> <path> <status> [body]   answer a request so: route GET /api/temp 200 {\"t\":21.5}
unroute <METHOD> <path>                 drop a route
routes                                  the routes
It also answers GET / with its routes, POST /echo with what came, and the files of its folder.";

impl Engine for Server {
    fn help(&self) -> &'static str {
        SERVER_HELP
    }

    fn left(&mut self, peer: PeerId, _io: &mut Io) {
        self.buffers.remove(&peer);
    }

    fn tick(&mut self, _now: Instant, io: &mut Io) {
        if !self.routes_changed {
            return;
        }
        self.routes_changed = false;
        let routes: Vec<serde_json::Value> = self
            .routes
            .iter()
            .map(|((method, path), route)| {
                json!({
                    "method": method,
                    "path": path,
                    "status": route.status,
                    "type": route.content_type,
                    "body": hex(&route.body),
                })
            })
            .collect();
        io.report(json!({ "type": "routes", "routes": routes }));
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let buffer = self.buffers.entry(peer).or_default();
        buffer.extend_from_slice(bytes);
        let mut requests = Vec::new();
        loop {
            match take(buffer, false, false) {
                Ok(Some(request)) => requests.push(request),
                Ok(None) => break,
                Err(problem) => {
                    io.bad(&format!(
                        "What came is not HTTP: {problem}. The client is dropped."
                    ));
                    buffer.clear();
                    io.drop_peer(peer);
                    return;
                }
            }
        }
        for request in requests {
            io.came(peer, &request.describe());
            let response = self.respond(&request);
            let mut words = request.start.split(' ');
            io.report(json!({
                "type": "heard",
                "peer": peer,
                "method": words.next().unwrap_or(""),
                "path": words.next().unwrap_or(""),
                "body": hex(&request.body),
                "status": status_of(&response.start),
            }));
            io.went(peer, &response.describe());
            io.send(Target::Peer(peer), response.encode());
            if response.header("connection") == Some("close") {
                io.drop_peer(peer);
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let command = words.next().unwrap_or_default().to_lowercase();
        let result = (|| -> Result<(), String> {
            match command.as_str() {
                "route" => {
                    let method = words.need("the method, such as GET")?.to_uppercase();
                    let path = words.need("the path, such as /api/temp")?;
                    let path = if path.starts_with('/') {
                        path
                    } else {
                        format!("/{path}")
                    };
                    let status: u16 = words.number_or("the status", 200)?;
                    let body = words.rest();
                    io.note(&format!(
                        "{method} {path} is answered with {status} {}.",
                        reason(status)
                    ));
                    self.routes_changed = true;
                    self.routes.insert(
                        (method, path),
                        Route {
                            status,
                            content_type: guess_type(&body).into(),
                            body,
                        },
                    );
                }
                "unroute" => {
                    let method = words.need("the method")?.to_uppercase();
                    let path = words.need("the path")?;
                    if self
                        .routes
                        .remove(&(method.clone(), path.clone()))
                        .is_none()
                    {
                        return Err(format!("There is no route for {method} {path}."));
                    }
                    self.routes_changed = true;
                    io.note(&format!("{method} {path} has no route now."));
                }
                "routes" => {
                    let lines: Vec<String> = self
                        .routes
                        .iter()
                        .map(|((method, path), route)| {
                            format!(
                                "{method} {path} -> {} {}: {}",
                                route.status,
                                reason(route.status),
                                payload_text(&route.body)
                            )
                        })
                        .collect();
                    for line in lines {
                        io.note(&line);
                    }
                    if !self.folder.is_empty() {
                        io.note(&format!("Files from {}", self.folder));
                    }
                }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{client_to, listening, server_on_loopback, shown, start};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn messages_come_whole_by_length_and_in_chunks() {
        let mut stream = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel".to_vec();
        assert_eq!(take(&mut stream, false, false).unwrap(), None);
        stream.extend_from_slice(b"loHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
        let first = take(&mut stream, false, false).unwrap().unwrap();
        assert_eq!(first.body, b"hello");
        let second = take(&mut stream, false, false).unwrap().unwrap();
        assert_eq!(second.body, b"abcde");
        assert!(stream.is_empty());
        let mut until_close = b"HTTP/1.0 200 OK\r\n\r\nall of it".to_vec();
        assert_eq!(take(&mut until_close, false, false).unwrap(), None);
        assert_eq!(
            take(&mut until_close, false, true).unwrap().unwrap().body,
            b"all of it"
        );
        assert!(take(&mut b"SSH-2.0-OpenSSH\r\n\r\n".to_vec(), false, false).is_err());
    }

    #[test]
    fn a_client_and_the_server_talk() {
        let (server, server_events) = start(
            Box::new(Server::new(ServerOptions::default())),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                host: "127.0.0.1".into(),
                port,
                headers: "Authorization: Bearer token".into(),
            })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        crate::net::tests::joined(&client_events);
        client.command("get /api/status");
        let text = shown(&client_events, r#"{"ok":true,"from":"netNIMA"}"#);
        assert!(text.contains("HTTP/1.1 200 OK"), "{text}");
        let request = shown(&server_events, "Authorization: Bearer token");
        assert!(
            request.contains(&format!("Host: 127.0.0.1:{port}")),
            "{request}"
        );

        server.command(r#"route PUT /led 201 {"led":"on"}"#);
        client.command(r#"put /led {"led":"on"}"#);
        shown(&client_events, "HTTP/1.1 201 Created");
        client.command("post /echo ping");
        let text = shown(&client_events, "ping");
        assert!(text.contains("text/plain"), "{text}");
        client.command("delete /led");
        shown(&client_events, "405 Method Not Allowed");
        client.command("head /nothing");
        shown(&client_events, "404 Not Found");
        client.command("get /");
        shown(&client_events, "netNIMA HTTP server");
    }

    #[test]
    fn the_view_hears_requests_responses_and_routes() {
        use crate::proto::tests::reported;
        let (server, server_events) = start(
            Box::new(Server::new(ServerOptions::default())),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let routes = reported(&server_events, "routes");
        assert_eq!(routes["routes"][0]["path"], "/api/status");
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                host: "127.0.0.1".into(),
                port,
                headers: String::new(),
            })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        crate::net::tests::joined(&client_events);

        client.command("get /api/status");
        assert_eq!(reported(&client_events, "request")["path"], "/api/status");
        let response = reported(&client_events, "response");
        assert_eq!(response["status"], 200);
        assert_eq!(response["body"], hex(br#"{"ok":true,"from":"netNIMA"}"#));
        assert!(response["ms"].is_number());
        let heard = reported(&server_events, "heard");
        assert_eq!(
            (&heard["method"], &heard["status"]),
            (&json!("GET"), &json!(200))
        );

        // The headers every request has, and the routes, as they change.
        client.command("header Authorization: Bearer abc");
        assert_eq!(
            reported(&client_events, "headers")["headers"],
            json!([["Authorization", "Bearer abc"]])
        );
        server.command("route POST /api/led 201 done");
        let routes = reported(&server_events, "routes");
        let led = routes["routes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|route| route["path"] == "/api/led")
            .unwrap()
            .clone();
        assert_eq!(
            (&led["method"], &led["status"]),
            (&json!("POST"), &json!(201))
        );
    }
}
