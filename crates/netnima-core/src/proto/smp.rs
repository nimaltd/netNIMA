//! MCUmgr's SMP over UDP, as Zephyr serves it on port 1337: a client that
//! asks a board for its state and its images and uploads new firmware, and
//! a device that answers as Zephyr would, to try the client, or a tool such
//! as mcumgr, against.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use super::cbor::Cbor;
use super::{Engine, Io, Words, hex, hex_text};
use crate::net::{PeerId, Target};

const READ: u8 = 0;
const READ_RSP: u8 = 1;
const WRITE: u8 = 2;
const WRITE_RSP: u8 = 3;

const OS: u16 = 0;
const IMAGE: u16 = 1;

/// The most image bytes one upload request carries, so it fits Zephyr's
/// usual 1024-byte UDP buffer with its header and CBOR around it.
const CHUNK: usize = 768;
/// How long the client waits for an answer before asking again.
const ANSWER_TIME: Duration = Duration::from_secs(3);

/// One SMP message: its 8-byte header and its CBOR body.
#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    pub op: u8,
    /// 1 for SMP version 2, 0 for the first.
    pub version: u8,
    pub flags: u8,
    pub group: u16,
    pub seq: u8,
    pub id: u8,
    pub body: Cbor,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body.encode();
        let mut out = Vec::with_capacity(8 + body.len());
        out.push((self.version & 3) << 3 | (self.op & 7));
        out.push(self.flags);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.group.to_be_bytes());
        out.push(self.seq);
        out.push(self.id);
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("it is shorter than SMP's 8-byte header".into());
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let body = bytes
            .get(8..8 + length)
            .ok_or("its body is shorter than its header says")?;
        let body = if body.is_empty() {
            Cbor::Map(Vec::new())
        } else {
            Cbor::decode(body)?.0
        };
        Ok(Self {
            op: bytes[0] & 7,
            version: (bytes[0] >> 3) & 3,
            flags: bytes[1],
            group: u16::from_be_bytes([bytes[4], bytes[5]]),
            seq: bytes[6],
            id: bytes[7],
            body,
        })
    }
}

fn group_name(group: u16) -> String {
    match group {
        OS => "os".into(),
        IMAGE => "image".into(),
        2 => "stat".into(),
        3 => "settings".into(),
        4 => "log".into(),
        5 => "crash".into(),
        8 => "fs".into(),
        9 => "shell".into(),
        10 => "enum".into(),
        63 => "zephyr".into(),
        other => format!("group {other}"),
    }
}

fn command_name(group: u16, id: u8) -> String {
    let name = match (group, id) {
        (OS, 0) => "echo",
        (OS, 2) => "taskstat",
        (OS, 3) => "mpstat",
        (OS, 4) => "datetime",
        (OS, 5) => "reset",
        (OS, 6) => "params",
        (OS, 7) => "info",
        (OS, 8) => "bootloader",
        (IMAGE, 0) => "state",
        (IMAGE, 1) => "upload",
        (IMAGE, 5) => "erase",
        (IMAGE, 6) => "slot info",
        (2, 0) => "group data",
        (2, 1) => "list groups",
        (8, 0) => "file",
        (9, 0) => "exec",
        (63, 0) => "erase storage",
        _ => return format!("command {id}"),
    };
    name.into()
}

fn op_name(op: u8) -> &'static str {
    match op {
        READ => "read",
        READ_RSP => "read answer",
        WRITE => "write",
        WRITE_RSP => "write answer",
        _ => "op ?",
    }
}

/// What an SMP error code says.
fn rc_text(rc: i128) -> &'static str {
    match rc {
        0 => "ok",
        1 => "unknown error",
        2 => "out of memory",
        3 => "invalid value",
        4 => "timed out",
        5 => "no such entry",
        6 => "bad state",
        7 => "message too large",
        8 => "not supported",
        9 => "corrupt",
        10 => "busy",
        11 => "access denied",
        12 => "the protocol is too old for it",
        13 => "the protocol is too new for it",
        _ => "an error SMP does not name",
    }
}

/// A frame in one line: its group, command and op, then its body.
pub fn describe(frame: &Frame) -> String {
    let mut line = format!(
        "{} {} {} (seq {}{})",
        group_name(frame.group),
        command_name(frame.group, frame.id),
        op_name(frame.op),
        frame.seq,
        if frame.version == 1 { ", SMP 2" } else { "" }
    );
    // Upload chunks are long: their data is said by its size.
    let body = match (&frame.body, frame.group, frame.id) {
        (Cbor::Map(entries), IMAGE, 1) => Cbor::Map(
            entries
                .iter()
                .map(|(key, value)| match value {
                    Cbor::Bytes(bytes) if bytes.len() > 40 => {
                        (key.clone(), Cbor::Text(format!("{} bytes", bytes.len())))
                    }
                    _ => (key.clone(), value.clone()),
                })
                .collect(),
        ),
        (body, _, _) => body.clone(),
    };
    line.push_str(&format!(": {body}"));
    if let Some(rc) = frame.body.get("rc").and_then(Cbor::as_int)
        && rc != 0
    {
        line.push_str(&format!("\nrc {rc}: {}", rc_text(rc)));
    }
    if let Some(err) = frame.body.get("err") {
        let rc = err.get("rc").and_then(Cbor::as_int).unwrap_or(0);
        line.push_str(&format!("\nerror {rc}: {}", rc_text(rc)));
    }
    line
}

/// A frame's result for the views: its rc, or SMP 2's err with its group.
fn result_json(body: &Cbor) -> serde_json::Value {
    let rc = body.get("rc").and_then(Cbor::as_int);
    let error = body.get("err").map(|err| {
        let rc = err.get("rc").and_then(Cbor::as_int).unwrap_or(0);
        json!({
            "group": err.get("group").and_then(Cbor::as_int).map(|group| group_name(group as u16)),
            "rc": rc as i64,
            "text": rc_text(rc),
        })
    });
    json!({
        "rc": rc.map(|rc| rc as i64),
        "rcText": rc.filter(|rc| *rc != 0).map(rc_text),
        "error": error,
    })
}

/// An image's version from its MCUboot header, if it has one: "1.2.3+4".
pub(crate) fn mcuboot_version(image: &[u8]) -> Option<String> {
    if image.len() < 32 || u32::from_le_bytes(image[0..4].try_into().ok()?) != 0x96f3_b83d {
        return None;
    }
    let revision = u16::from_le_bytes([image[22], image[23]]);
    let build = u32::from_le_bytes(image[24..28].try_into().ok()?);
    Some(format!("{}.{}.{revision}+{build}", image[20], image[21]))
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(char::is_ascii_hexdigit).collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err(format!("{text} is not a hash in hex."));
    }
    Ok((0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap_or(0))
        .collect())
}

// ----- The client -----

/// An MCUmgr client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// Speaks SMP version 2, as Zephyr 3.5 and later do.
    pub version2: bool,
    /// The folder firmware files are read from: empty for Downloads.
    pub folder: String,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            version2: true,
            folder: String::new(),
        }
    }
}

/// An upload going on.
struct Upload {
    name: String,
    data: Vec<u8>,
    image: i128,
    sha: Vec<u8>,
    offset: usize,
    started: Instant,
    shown: usize,
    /// Its version, from its MCUboot header.
    version: Option<String>,
}

impl Upload {
    /// Tells the view how the upload goes.
    fn report(&self, problem: Option<String>, io: &mut Io) {
        let seconds = self.started.elapsed().as_secs_f64().max(0.001);
        io.report(json!({
            "type": "upload",
            "name": self.name,
            "image": self.image as i64,
            "version": self.version,
            "sha": hex(&self.sha),
            "sent": self.offset,
            "total": self.data.len(),
            "done": problem.is_none() && self.offset >= self.data.len(),
            "problem": problem,
            "kbps": self.offset as f64 / 1024.0 / seconds,
        }));
    }
}

pub struct Client {
    version: u8,
    folder: PathBuf,
    seq: u8,
    /// The last request, sent again if no answer comes.
    asked: Option<(Frame, Instant, u32)>,
    upload: Option<Upload>,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let folder = if options.folder.trim().is_empty() {
            std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .map_or_else(|| PathBuf::from("."), PathBuf::from)
                .join("Downloads")
        } else {
            PathBuf::from(options.folder.trim())
        };
        Self {
            version: u8::from(options.version2),
            folder,
            seq: 0,
            asked: None,
            upload: None,
        }
    }

    fn send(&mut self, op: u8, group: u16, id: u8, body: Cbor, io: &mut Io, quiet: bool) {
        self.seq = self.seq.wrapping_add(1);
        let frame = Frame {
            op,
            version: self.version,
            flags: 0,
            group,
            seq: self.seq,
            id,
            body,
        };
        if !quiet {
            io.went(0, &describe(&frame));
            io.report(json!({
                "type": "request",
                "group": group_name(group),
                "command": command_name(group, id),
                "op": op_name(op),
                "seq": frame.seq,
            }));
        }
        io.send(Target::Default, frame.encode());
        self.asked = Some((frame, Instant::now(), 0));
    }

    fn next_chunk(&mut self, io: &mut Io) {
        let Some(upload) = &self.upload else {
            return;
        };
        let end = (upload.offset + CHUNK).min(upload.data.len());
        let mut entries = vec![
            ("off", Cbor::Int(upload.offset as i128)),
            (
                "data",
                Cbor::Bytes(upload.data[upload.offset..end].to_vec()),
            ),
        ];
        if upload.offset == 0 {
            entries.insert(0, ("image", Cbor::Int(upload.image)));
            entries.insert(1, ("len", Cbor::Int(upload.data.len() as i128)));
            entries.push(("sha", Cbor::Bytes(upload.sha.clone())));
        }
        let quiet = upload.offset != 0;
        self.send(WRITE, IMAGE, 1, Cbor::map(entries), io, quiet);
    }
}

const CLIENT_HELP: &str = "echo <text>              os echo: the board says it back
info                     os info: what the board is
params                   os params: its buffer size and count
taskstat                 os taskstat: its threads
datetime                 os datetime: its clock
reset                    os reset: restart it
images                   image state: the images and their hashes
upload <file> [image]    image upload, a file of the tab's folder, such as zephyr.signed.bin
test <hash>              mark an image to run once at the next reset
confirm [hash]           keep the image that runs, or the one named
erase                    erase the image slot not running";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let frame = match Frame::decode(bytes) {
            Ok(frame) => frame,
            Err(problem) => {
                io.bad(&format!("Not SMP: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        let mut ms = None;
        if let Some((asked, sent, _)) = &self.asked
            && asked.seq == frame.seq
        {
            ms = Some(sent.elapsed().as_secs_f64() * 1000.0);
            self.asked = None;
        }
        let uploading = frame.group == IMAGE && frame.id == 1 && self.upload.is_some();
        if !uploading {
            io.came(peer, &describe(&frame));
            let mut report = json!({
                "type": "answer",
                "group": group_name(frame.group),
                "command": command_name(frame.group, frame.id),
                "op": op_name(frame.op),
                "seq": frame.seq,
                "body": frame.body.to_json(),
                "ms": ms,
            });
            if let (Some(report), serde_json::Value::Object(result)) =
                (report.as_object_mut(), result_json(&frame.body))
            {
                report.extend(result);
            }
            io.report(report);
            return;
        }
        let rc = frame.body.get("rc").and_then(Cbor::as_int).unwrap_or(0);
        let error = frame.body.get("err").is_some();
        let Some(upload) = &mut self.upload else {
            return;
        };
        if rc != 0 || error {
            io.came(peer, &describe(&frame));
            io.bad(&format!("The upload of {} stopped.", upload.name));
            let code = frame
                .body
                .get("err")
                .and_then(|err| err.get("rc"))
                .and_then(Cbor::as_int)
                .unwrap_or(rc);
            upload.report(Some(format!("rc {code}: {}", rc_text(code))), io);
            self.upload = None;
            return;
        }
        let offset = frame.body.get("off").and_then(Cbor::as_int).unwrap_or(0) as usize;
        let before = upload.offset * 100 / upload.data.len();
        upload.offset = offset.min(upload.data.len());
        // The view hears each percent.
        if upload.offset * 100 / upload.data.len() != before || upload.offset >= upload.data.len() {
            upload.report(None, io);
        }
        // A line now and then: every tenth of the way.
        let tenth = upload.data.len() / 10 + 1;
        if upload.offset / tenth != upload.shown / tenth || upload.offset == upload.data.len() {
            upload.shown = upload.offset;
            io.came(
                peer,
                &format!(
                    "image upload: {} of {} bytes",
                    upload.offset,
                    upload.data.len()
                ),
            );
        }
        if upload.offset >= upload.data.len() {
            let seconds = upload.started.elapsed().as_secs_f64().max(0.001);
            io.note(&format!(
                "{} uploaded: {} bytes in {seconds:.1} s, {:.1} KB/s. Type images to see it, test <hash> to run it.",
                upload.name,
                upload.data.len(),
                upload.data.len() as f64 / 1024.0 / seconds
            ));
            self.upload = None;
        } else {
            self.next_chunk(io);
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            let command = words.next().unwrap_or_default().to_lowercase();
            match command.as_str() {
                "echo" => self.send(
                    WRITE,
                    OS,
                    0,
                    Cbor::map(vec![("d", Cbor::Text(words.rest_text()))]),
                    io,
                    false,
                ),
                "info" => self.send(
                    READ,
                    OS,
                    7,
                    Cbor::map(vec![(
                        "format",
                        Cbor::Text(words.next().unwrap_or_else(|| "a".into())),
                    )]),
                    io,
                    false,
                ),
                "params" => self.send(READ, OS, 6, Cbor::Map(Vec::new()), io, false),
                "taskstat" => self.send(READ, OS, 2, Cbor::Map(Vec::new()), io, false),
                "datetime" => self.send(READ, OS, 4, Cbor::Map(Vec::new()), io, false),
                "reset" => self.send(WRITE, OS, 5, Cbor::Map(Vec::new()), io, false),
                "images" | "state" => self.send(READ, IMAGE, 0, Cbor::Map(Vec::new()), io, false),
                "erase" => self.send(WRITE, IMAGE, 5, Cbor::Map(Vec::new()), io, false),
                "test" => {
                    let hash = hex_bytes(&words.need("the image's hash, as images shows it")?)?;
                    self.send(
                        WRITE,
                        IMAGE,
                        0,
                        Cbor::map(vec![
                            ("hash", Cbor::Bytes(hash)),
                            ("confirm", Cbor::Bool(false)),
                        ]),
                        io,
                        false,
                    );
                }
                "confirm" => {
                    let mut entries = vec![("confirm", Cbor::Bool(true))];
                    if let Some(hash) = words.next() {
                        entries.insert(0, ("hash", Cbor::Bytes(hex_bytes(&hash)?)));
                    }
                    self.send(WRITE, IMAGE, 0, Cbor::map(entries), io, false);
                }
                "upload" => {
                    if self.upload.is_some() {
                        return Err("An upload is going on.".into());
                    }
                    let name = words.need("the file, such as zephyr.signed.bin")?;
                    let image: i128 = words.number_or("the image number", 0)?;
                    let path = if std::path::Path::new(&name).is_absolute() {
                        PathBuf::from(&name)
                    } else {
                        self.folder.join(&name)
                    };
                    let data = std::fs::read(&path)
                        .map_err(|error| format!("Could not read {}: {error}", path.display()))?;
                    if data.is_empty() {
                        return Err(format!("{} is empty.", path.display()));
                    }
                    let version = mcuboot_version(&data)
                        .map(|version| format!(", version {version}"))
                        .unwrap_or_else(|| ", with no MCUboot header".into());
                    io.note(&format!("Uploading {} bytes{version}.", data.len()));
                    let upload = Upload {
                        name,
                        sha: sha256(&data),
                        version: mcuboot_version(&data),
                        data,
                        image,
                        offset: 0,
                        started: Instant::now(),
                        shown: 0,
                    };
                    upload.report(None, io);
                    self.upload = Some(upload);
                    self.next_chunk(io);
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

    fn tick(&mut self, now: Instant, io: &mut Io) {
        let Some((frame, sent, tries)) = &mut self.asked else {
            return;
        };
        if now.duration_since(*sent) < ANSWER_TIME {
            return;
        }
        if *tries >= 3 {
            io.bad(&format!(
                "No answer to {} {} after 4 tries: is an SMP server on that port?",
                group_name(frame.group),
                command_name(frame.group, frame.id)
            ));
            io.report(json!({
                "type": "timeout",
                "group": group_name(frame.group),
                "command": command_name(frame.group, frame.id),
                "tries": *tries + 1,
            }));
            if let Some(upload) = &self.upload {
                upload.report(Some("The board did not answer.".into()), io);
            }
            self.asked = None;
            self.upload = None;
            return;
        }
        *tries += 1;
        *sent = now;
        io.went(0, &format!("{} (again)", describe(frame)));
        io.send(Target::Default, frame.encode());
    }
}

// ----- The device -----

/// One image slot of the simulated device.
struct Slot {
    version: String,
    hash: Vec<u8>,
    bootable: bool,
    pending: bool,
    confirmed: bool,
    active: bool,
}

/// Answers SMP as a Zephyr board would: echo, info, params, taskstat,
/// datetime and reset, and image state, upload, test, confirm and erase.
pub struct Device {
    slots: Vec<Slot>,
    /// The image being uploaded into the second slot.
    receiving: Vec<u8>,
    expected: usize,
    datetime: String,
    /// Whether its images changed since the view was told, as it is on the
    /// next tick.
    changed: bool,
}

impl Default for Device {
    fn default() -> Self {
        let running = b"netNIMA's simulated firmware, version 1.0.0".to_vec();
        Self {
            slots: vec![Slot {
                version: "1.0.0".into(),
                hash: sha256(&running),
                bootable: true,
                pending: false,
                confirmed: true,
                active: true,
            }],
            receiving: Vec::new(),
            expected: 0,
            datetime: String::new(),
            changed: true,
        }
    }
}

impl Device {
    /// Tells the view its images, and an upload coming in.
    fn report_images(&mut self, io: &mut Io) {
        self.changed = false;
        let images: Vec<serde_json::Value> = self
            .slots
            .iter()
            .enumerate()
            .map(|(slot, image)| {
                json!({
                    "image": 0,
                    "slot": slot,
                    "version": image.version,
                    "hash": hex(&image.hash),
                    "bootable": image.bootable,
                    "pending": image.pending,
                    "confirmed": image.confirmed,
                    "active": image.active,
                })
            })
            .collect();
        let receiving = (self.expected > 0 && self.receiving.len() < self.expected)
            .then(|| json!({ "got": self.receiving.len(), "total": self.expected }));
        io.report(json!({ "type": "images", "images": images, "receiving": receiving }));
    }
    fn images(&self) -> Cbor {
        let images = self
            .slots
            .iter()
            .enumerate()
            .map(|(slot, image)| {
                Cbor::map(vec![
                    ("image", Cbor::Int(0)),
                    ("slot", Cbor::Int(slot as i128)),
                    ("version", Cbor::Text(image.version.clone())),
                    ("hash", Cbor::Bytes(image.hash.clone())),
                    ("bootable", Cbor::Bool(image.bootable)),
                    ("pending", Cbor::Bool(image.pending)),
                    ("confirmed", Cbor::Bool(image.confirmed)),
                    ("active", Cbor::Bool(image.active)),
                    ("permanent", Cbor::Bool(false)),
                ])
            })
            .collect();
        Cbor::map(vec![
            ("images", Cbor::Array(images)),
            ("splitStatus", Cbor::Int(0)),
        ])
    }

    fn answer(&mut self, frame: &Frame, io: &mut Io) -> Cbor {
        let body = &frame.body;
        match (frame.group, frame.id, frame.op) {
            (OS, 0, WRITE) => Cbor::map(vec![(
                "r",
                body.get("d").cloned().unwrap_or(Cbor::Text(String::new())),
            )]),
            (OS, 2, READ) => {
                let task = |priority: i128, stack: i128, used: i128| {
                    Cbor::map(vec![
                        ("prio", Cbor::Int(priority)),
                        ("tid", Cbor::Int(priority + 1)),
                        ("state", Cbor::Int(0)),
                        ("stkuse", Cbor::Int(used)),
                        ("stksiz", Cbor::Int(stack)),
                        ("cswcnt", Cbor::Int(0)),
                        ("runtime", Cbor::Int(0)),
                    ])
                };
                Cbor::map(vec![(
                    "tasks",
                    Cbor::map(vec![
                        ("main", task(0, 2048, 712)),
                        ("idle", task(15, 320, 64)),
                        ("net_rx", task(8, 1500, 400)),
                    ]),
                )])
            }
            (OS, 4, READ) => {
                let now = if self.datetime.is_empty() {
                    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
                } else {
                    self.datetime.clone()
                };
                Cbor::map(vec![("datetime", Cbor::Text(now))])
            }
            (OS, 4, WRITE) => {
                self.datetime = body
                    .get("datetime")
                    .and_then(Cbor::as_text)
                    .unwrap_or_default()
                    .to_string();
                Cbor::Map(Vec::new())
            }
            (OS, 5, WRITE) => {
                io.note("Asked to reset: a board would restart now.");
                // A test image runs after the reset.
                if let Some(pending) = self.slots.iter().position(|slot| slot.pending) {
                    for (index, slot) in self.slots.iter_mut().enumerate() {
                        slot.active = index == pending;
                        slot.pending = false;
                    }
                }
                Cbor::Map(Vec::new())
            }
            (OS, 6, READ) => Cbor::map(vec![
                ("buf_size", Cbor::Int(1024)),
                ("buf_count", Cbor::Int(4)),
            ]),
            (OS, 7, READ) => Cbor::map(vec![(
                "output",
                Cbor::Text("netNIMA SMP device (simulated Zephyr) on a PC".into()),
            )]),
            (IMAGE, 0, READ) => self.images(),
            (IMAGE, 0, WRITE) => {
                let confirm = matches!(body.get("confirm"), Some(Cbor::Bool(true)));
                let hash = body
                    .get("hash")
                    .and_then(Cbor::as_bytes)
                    .map(<[u8]>::to_vec);
                let found = match &hash {
                    Some(hash) => self.slots.iter().position(|slot| &slot.hash == hash),
                    None => self.slots.iter().position(|slot| slot.active),
                };
                match found {
                    Some(index) => {
                        let slot = &mut self.slots[index];
                        if confirm {
                            slot.confirmed = true;
                        } else {
                            slot.pending = true;
                        }
                        self.images()
                    }
                    None => Cbor::map(vec![("rc", Cbor::Int(3))]),
                }
            }
            (IMAGE, 1, WRITE) => {
                let offset = body.get("off").and_then(Cbor::as_int).unwrap_or(0) as usize;
                let data = body
                    .get("data")
                    .and_then(Cbor::as_bytes)
                    .unwrap_or_default();
                if offset == 0 {
                    self.expected = body.get("len").and_then(Cbor::as_int).unwrap_or(0) as usize;
                    self.receiving.clear();
                }
                if offset != self.receiving.len() {
                    // Not where it left off: it says where it is.
                    return Cbor::map(vec![
                        ("rc", Cbor::Int(0)),
                        ("off", Cbor::Int(self.receiving.len() as i128)),
                    ]);
                }
                self.receiving.extend_from_slice(data);
                if self.expected > 0 && self.receiving.len() >= self.expected {
                    let version =
                        mcuboot_version(&self.receiving).unwrap_or_else(|| "0.0.0".into());
                    let hash = sha256(&self.receiving);
                    io.note(&format!(
                        "An image of {} bytes came, version {version}.",
                        self.receiving.len()
                    ));
                    self.slots.truncate(1);
                    self.slots.push(Slot {
                        version,
                        hash,
                        bootable: true,
                        pending: false,
                        confirmed: false,
                        active: false,
                    });
                }
                Cbor::map(vec![
                    ("rc", Cbor::Int(0)),
                    ("off", Cbor::Int(self.receiving.len() as i128)),
                ])
            }
            (IMAGE, 5, WRITE) => {
                self.slots.truncate(1);
                self.receiving.clear();
                Cbor::map(vec![("rc", Cbor::Int(0))])
            }
            _ => Cbor::map(vec![("rc", Cbor::Int(8))]),
        }
    }
}

impl Engine for Device {
    fn help(&self) -> &'static str {
        "It answers SMP as a Zephyr board would: os echo, info, params, taskstat, datetime, reset;
image state, upload, test, confirm and erase.
images      the images it has"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let frame = match Frame::decode(bytes) {
            Ok(frame) => frame,
            Err(problem) => {
                io.bad(&format!("Not SMP: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        // Upload chunks are many: only the first and the last are shown.
        let chunk_offset = (frame.group == IMAGE && frame.id == 1)
            .then(|| frame.body.get("off").and_then(Cbor::as_int).unwrap_or(0));
        let quiet = chunk_offset.is_some_and(|offset| offset != 0);
        if !quiet {
            io.came(peer, &describe(&frame));
        }
        let body = self.answer(&frame, io);
        if frame.group == IMAGE || (frame.group, frame.id) == (OS, 5) {
            self.changed = true;
        }
        let answer = Frame {
            op: if frame.op == READ {
                READ_RSP
            } else {
                WRITE_RSP
            },
            version: frame.version,
            flags: 0,
            group: frame.group,
            seq: frame.seq,
            id: frame.id,
            body,
        };
        let done =
            chunk_offset.is_some() && self.expected > 0 && self.receiving.len() >= self.expected;
        if !quiet || done {
            io.went(peer, &describe(&answer));
            // An upload's chunk is said by its size, not its data; the
            // first one says the image's length too.
            let asked = match (chunk_offset, frame.body.get("data")) {
                (Some(offset), Some(Cbor::Bytes(data))) => {
                    let mut chunk = json!({
                        "off": offset as i64,
                        "data": format!("{} bytes", data.len()),
                    });
                    if let Some(len) = frame.body.get("len").and_then(Cbor::as_int) {
                        chunk["len"] = json!(len as i64);
                    }
                    chunk
                }
                _ => frame.body.to_json(),
            };
            let mut report = json!({
                "type": "heard",
                "peer": peer,
                "group": group_name(frame.group),
                "command": command_name(frame.group, frame.id),
                "op": op_name(frame.op),
                "seq": frame.seq,
                "body": asked,
            });
            if let (Some(report), serde_json::Value::Object(result)) =
                (report.as_object_mut(), result_json(&answer.body))
            {
                report.extend(result);
            }
            io.report(report);
        }
        io.send(Target::Peer(peer), answer.encode());
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "images" => io.note(&self.images().to_string()),
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, _now: Instant, io: &mut Io) {
        if self.changed {
            self.report_images(io);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{listening, reported, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn frames_read_back_as_they_were_written() {
        let frame = Frame {
            op: WRITE,
            version: 1,
            flags: 0,
            group: OS,
            seq: 7,
            id: 0,
            body: Cbor::map(vec![("d", Cbor::Text("hi".into()))]),
        };
        let bytes = frame.encode();
        assert_eq!(&bytes[..8], &[0x0a, 0, 0, 6, 0, 0, 7, 0]);
        assert_eq!(Frame::decode(&bytes).unwrap(), frame);
        assert_eq!(
            describe(&frame),
            r#"os echo write (seq 7, SMP 2): {"d": "hi"}"#
        );
    }

    #[test]
    fn the_client_asks_the_device_and_uploads_an_image() {
        let folder = crate::certs::tests::scratch("smp");
        // An MCUboot header with version 2.1.3+4, then the image.
        let mut image = vec![0u8; 32];
        image[0..4].copy_from_slice(&0x96f3_b83du32.to_le_bytes());
        image[20] = 2;
        image[21] = 1;
        image[22..24].copy_from_slice(&3u16.to_le_bytes());
        image[24..28].copy_from_slice(&4u32.to_le_bytes());
        image.extend((0..5000u32).map(|n| n as u8));
        std::fs::write(folder.join("zephyr.signed.bin"), &image).unwrap();

        let (_device, device_events) = start(
            Box::new(Device::default()),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&device_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                version2: true,
                folder: folder.display().to_string(),
            })),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);
        client.command("echo hello board");
        shown(
            &client_events,
            r#"os echo write answer (seq 1, SMP 2): {"r": "hello board"}"#,
        );
        client.command("params");
        shown(&client_events, r#""buf_size": 1024"#);
        client.command("upload zephyr.signed.bin");
        shown(&client_events, "zephyr.signed.bin uploaded: 5032 bytes");
        client.command("images");
        let text = shown(&client_events, r#""version": "2.1.3+4""#);
        assert!(text.contains(r#""slot": 1"#), "{text}");
        client.command("taskstat");
        shown(&client_events, r#""main""#);
        let _ = std::fs::remove_dir_all(folder);
    }

    /// The first report of type `kind` that `wanted` takes.
    fn reported_when(
        events: &std::sync::mpsc::Receiver<crate::net::Event>,
        kind: &str,
        wanted: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        loop {
            let report = reported(events, kind);
            if wanted(&report) {
                return report;
            }
        }
    }

    #[test]
    fn the_views_hear_answers_uploads_and_images() {
        let folder = crate::certs::tests::scratch("smp-views");
        let mut image = vec![0u8; 32];
        image[0..4].copy_from_slice(&0x96f3_b83du32.to_le_bytes());
        image[20] = 1;
        image[21] = 4;
        image.extend((0..3000u32).map(|n| n as u8));
        std::fs::write(folder.join("app.bin"), &image).unwrap();

        let (_device, device_events) = start(
            Box::new(Device::default()),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&device_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                version2: true,
                folder: folder.display().to_string(),
            })),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);
        let first = reported(&device_events, "images");
        assert_eq!(first["images"].as_array().unwrap().len(), 1);
        assert_eq!(first["images"][0]["active"], true);

        client.command("echo hi there");
        let request = reported(&client_events, "request");
        assert_eq!(request["command"], "echo");
        let answer = reported(&client_events, "answer");
        assert_eq!(answer["group"], "os");
        assert_eq!(answer["command"], "echo");
        assert_eq!(answer["op"], "write answer");
        assert_eq!(answer["body"], json!({ "r": "hi there" }));
        assert!(answer["ms"].as_f64().is_some());
        let heard = reported(&device_events, "heard");
        assert_eq!(heard["command"], "echo");
        assert_eq!(heard["body"], json!({ "d": "hi there" }));

        client.command("upload app.bin");
        let done = reported_when(&client_events, "upload", |report| {
            report["done"] == true || !report["problem"].is_null()
        });
        assert!(done["problem"].is_null(), "{done}");
        assert_eq!(done["sent"], 3032);
        assert_eq!(done["version"], "1.4.0+0");
        let images = reported_when(&device_events, "images", |report| {
            report["images"]
                .as_array()
                .is_some_and(|all| all.len() == 2)
        });
        assert_eq!(images["images"][1]["version"], "1.4.0+0");
        assert_eq!(images["images"][1]["hash"], done["sha"]);

        // Marked to test: an answer with the images, the second pending.
        client.command(&format!("test {}", done["sha"].as_str().unwrap()));
        let answer = reported_when(&client_events, "answer", |report| {
            report["command"] == "state"
        });
        assert_eq!(answer["body"]["images"][1]["pending"], true);
        client.command("test 00ff");
        let refused = reported_when(&client_events, "answer", |report| {
            report["command"] == "state"
        });
        assert_eq!(refused["rc"], 3);
        assert_eq!(refused["rcText"], "invalid value");
        let _ = std::fs::remove_dir_all(folder);
    }
}
