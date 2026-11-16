//! Modbus TCP: a master that reads and writes a device's coils and
//! registers, and a slave with all four tables, to test a master against.
//!
//! Each request and answer is shown with what it means, such as
//! "Read Holding Registers 0 to 9" and the values in decimal and hex.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Engine, Io, Words, hex_text};
use crate::net::{Peer, PeerId, Target};

const READ_COILS: u8 = 0x01;
const READ_DISCRETE: u8 = 0x02;
const READ_HOLDING: u8 = 0x03;
const READ_INPUT: u8 = 0x04;
const WRITE_COIL: u8 = 0x05;
const WRITE_REGISTER: u8 = 0x06;
const WRITE_COILS: u8 = 0x0F;
const WRITE_REGISTERS: u8 = 0x10;
const READ_WRITE_REGISTERS: u8 = 0x17;

/// How long the master waits for an answer.
const ANSWER_TIME: Duration = Duration::from_secs(2);

fn function_name(function: u8) -> String {
    match function & 0x7f {
        READ_COILS => "Read Coils".into(),
        READ_DISCRETE => "Read Discrete Inputs".into(),
        READ_HOLDING => "Read Holding Registers".into(),
        READ_INPUT => "Read Input Registers".into(),
        WRITE_COIL => "Write Single Coil".into(),
        WRITE_REGISTER => "Write Single Register".into(),
        0x07 => "Read Exception Status".into(),
        0x08 => "Diagnostics".into(),
        0x0B => "Get Comm Event Counter".into(),
        WRITE_COILS => "Write Multiple Coils".into(),
        WRITE_REGISTERS => "Write Multiple Registers".into(),
        0x11 => "Report Server ID".into(),
        0x16 => "Mask Write Register".into(),
        READ_WRITE_REGISTERS => "Read/Write Multiple Registers".into(),
        0x2B => "Read Device Identification".into(),
        other => format!("function {other:#04x}"),
    }
}

fn exception_name(code: u8) -> &'static str {
    match code {
        1 => "Illegal Function",
        2 => "Illegal Data Address",
        3 => "Illegal Data Value",
        4 => "Server Device Failure",
        5 => "Acknowledge",
        6 => "Server Device Busy",
        8 => "Memory Parity Error",
        0x0A => "Gateway Path Unavailable",
        0x0B => "Gateway Target Device Failed to Respond",
        _ => "an exception Modbus does not name",
    }
}

/// One frame: the MBAP header's transaction and unit, and the PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub transaction: u16,
    pub unit: u8,
    pub pdu: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + self.pdu.len());
        out.extend_from_slice(&self.transaction.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&((self.pdu.len() + 1) as u16).to_be_bytes());
        out.push(self.unit);
        out.extend_from_slice(&self.pdu);
        out
    }
}

/// Takes the first whole frame off a stream's bytes, if one is there.
pub fn take(buffer: &mut Vec<u8>) -> Result<Option<Frame>, String> {
    if buffer.len() < 7 {
        return Ok(None);
    }
    let protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
    if protocol != 0 {
        return Err(format!("the protocol id is {protocol}, not Modbus's 0"));
    }
    let length = usize::from(u16::from_be_bytes([buffer[4], buffer[5]]));
    if !(2..=254).contains(&length) {
        return Err(format!("a frame says it is {length} bytes long"));
    }
    if buffer.len() < 6 + length {
        return Ok(None);
    }
    let frame = Frame {
        transaction: u16::from_be_bytes([buffer[0], buffer[1]]),
        unit: buffer[6],
        pdu: buffer[7..6 + length].to_vec(),
    };
    buffer.drain(..6 + length);
    Ok(Some(frame))
}

/// Modbus RTU's CRC-16, sent low byte first.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// An RTU frame: the unit, the PDU and the CRC, with no MBAP header, as
/// gateways pass RTU through over TCP.
pub fn encode_rtu(unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pdu.len() + 3);
    out.push(unit);
    out.extend_from_slice(pdu);
    let crc = crc16(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// Takes the first whole RTU frame off a stream. RTU says no length: it is
/// found from the function, and whether it is an answer or a request.
pub fn take_rtu(buffer: &mut Vec<u8>, answer: bool) -> Result<Option<Frame>, String> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let function = buffer[1];
    let length = if function & 0x80 != 0 {
        5
    } else {
        match (function, answer) {
            (READ_COILS..=READ_INPUT | READ_WRITE_REGISTERS, true) => match buffer.get(2) {
                Some(count) => 5 + usize::from(*count),
                None => return Ok(None),
            },
            (READ_COILS..=WRITE_REGISTER, _) | (WRITE_COILS | WRITE_REGISTERS, true) => 8,
            (WRITE_COILS | WRITE_REGISTERS, false) => match buffer.get(6) {
                Some(count) => 9 + usize::from(*count),
                None => return Ok(None),
            },
            (READ_WRITE_REGISTERS, false) => match buffer.get(10) {
                Some(count) => 13 + usize::from(*count),
                None => return Ok(None),
            },
            _ => {
                return Err(format!(
                    "function {function:#04x} is not one netNIMA can cut from an RTU stream"
                ));
            }
        }
    };
    if buffer.len() < length {
        return Ok(None);
    }
    let frame: Vec<u8> = buffer.drain(..length).collect();
    let crc = u16::from_le_bytes([frame[length - 2], frame[length - 1]]);
    if crc16(&frame[..length - 2]) != crc {
        return Err(format!(
            "the CRC is wrong: {crc:#06x}, not {:#06x}",
            crc16(&frame[..length - 2])
        ));
    }
    Ok(Some(Frame {
        transaction: 0,
        unit: frame[0],
        pdu: frame[1..length - 2].to_vec(),
    }))
}

fn word(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

/// Registers as people read them: "0=1234 (0x04d2)  1=0".
fn registers_text(start: u16, values: &[u16]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let address = start.wrapping_add(index as u16);
            if *value > 9 {
                format!("{address}={value} ({value:#06x})")
            } else {
                format!("{address}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

/// Coils as people read them: "0=1 1=0 2=1".
fn bits_text(start: u16, values: &[bool]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, on)| format!("{}={}", start.wrapping_add(index as u16), u8::from(*on)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn pack_bits(values: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0u8; values.len().div_ceil(8)];
    for (index, on) in values.iter().enumerate() {
        if *on {
            bytes[index / 8] |= 1 << (index % 8);
        }
    }
    bytes
}

fn unpack_bits(bytes: &[u8], count: usize) -> Vec<bool> {
    (0..count)
        .map(|index| {
            bytes
                .get(index / 8)
                .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
        })
        .collect()
}

/// What a request asks, in words.
pub fn describe_request(pdu: &[u8]) -> String {
    let Some(&function) = pdu.first() else {
        return "an empty request".into();
    };
    let name = function_name(function);
    let start = word(pdu, 1).unwrap_or(0);
    let count = word(pdu, 3).unwrap_or(0);
    match function {
        READ_COILS | READ_DISCRETE | READ_HOLDING | READ_INPUT => {
            format!(
                "{name} {start} to {}",
                start.wrapping_add(count).wrapping_sub(1)
            )
        }
        WRITE_COIL => format!(
            "{name} {start} = {}",
            if count == 0xFF00 { "on" } else { "off" }
        ),
        WRITE_REGISTER => format!("{name} {start} = {count} ({count:#06x})"),
        WRITE_COILS => format!(
            "{name}: {}",
            bits_text(
                start,
                &unpack_bits(pdu.get(6..).unwrap_or(&[]), usize::from(count))
            )
        ),
        WRITE_REGISTERS => {
            let values: Vec<u16> = (0..usize::from(count))
                .filter_map(|index| word(pdu, 6 + index * 2))
                .collect();
            format!("{name}: {}", registers_text(start, &values))
        }
        READ_WRITE_REGISTERS => {
            let write_start = word(pdu, 5).unwrap_or(0);
            let write_count = word(pdu, 7).unwrap_or(0);
            let values: Vec<u16> = (0..usize::from(write_count))
                .filter_map(|index| word(pdu, 10 + index * 2))
                .collect();
            format!(
                "{name}: read {start} to {}, write {}",
                start.wrapping_add(count).wrapping_sub(1),
                registers_text(write_start, &values)
            )
        }
        _ => format!("{name}: {}", hex_text(&pdu[1..])),
    }
}

/// What an answer says, in words; `asked` is the request it answers, for
/// the addresses its values start at.
pub fn describe_answer(pdu: &[u8], asked: Option<&[u8]>) -> String {
    let Some(&function) = pdu.first() else {
        return "an empty answer".into();
    };
    if function & 0x80 != 0 {
        let code = pdu.get(1).copied().unwrap_or(0);
        return format!(
            "{}: exception {code}, {}",
            function_name(function),
            exception_name(code)
        );
    }
    let start = asked.and_then(|asked| word(asked, 1)).unwrap_or(0);
    let count = asked.and_then(|asked| word(asked, 3)).unwrap_or(0);
    let data = pdu.get(2..).unwrap_or(&[]);
    match function {
        READ_COILS | READ_DISCRETE => {
            let count = if asked.is_some() {
                usize::from(count)
            } else {
                data.len() * 8
            };
            format!(
                "{}: {}",
                function_name(function),
                bits_text(start, &unpack_bits(data, count))
            )
        }
        READ_HOLDING | READ_INPUT | READ_WRITE_REGISTERS => {
            let values: Vec<u16> = data
                .chunks(2)
                .filter(|pair| pair.len() == 2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            format!(
                "{}: {}",
                function_name(function),
                registers_text(start, &values)
            )
        }
        WRITE_COIL | WRITE_REGISTER => format!("{}: done", describe_request(pdu)),
        WRITE_COILS | WRITE_REGISTERS => {
            let start = word(pdu, 1).unwrap_or(0);
            let count = word(pdu, 3).unwrap_or(0);
            format!(
                "{}: {start} to {} written",
                function_name(function),
                start.wrapping_add(count).wrapping_sub(1)
            )
        }
        _ => format!("{}: {}", function_name(function), hex_text(&pdu[1..])),
    }
}

// ----- The master -----

/// A Modbus TCP master tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct MasterOptions {
    /// The unit, or slave, id requests go to.
    pub unit: u8,
    /// RTU frames with a CRC, rather than MBAP headers: Modbus RTU over TCP.
    pub rtu: bool,
}

impl Default for MasterOptions {
    fn default() -> Self {
        Self {
            unit: 1,
            rtu: false,
        }
    }
}

struct Poll {
    line: String,
    every: Duration,
    next: Instant,
}

pub struct Master {
    unit: u8,
    rtu: bool,
    peer: Option<PeerId>,
    buffer: Vec<u8>,
    transaction: u16,
    /// Requests sent and not answered, by transaction.
    asked: BTreeMap<u16, (Vec<u8>, Instant)>,
    poll: Option<Poll>,
}

impl Master {
    pub fn new(options: MasterOptions) -> Self {
        Self {
            unit: options.unit,
            rtu: options.rtu,
            peer: None,
            buffer: Vec::new(),
            transaction: 0,
            asked: BTreeMap::new(),
            poll: None,
        }
    }

    fn ask(&mut self, pdu: Vec<u8>, io: &mut Io) {
        let Some(peer) = self.peer else {
            io.bad("Not connected: nothing was sent.");
            return;
        };
        self.transaction = self.transaction.wrapping_add(1);
        let frame = Frame {
            transaction: self.transaction,
            unit: self.unit,
            pdu: pdu.clone(),
        };
        if self.rtu {
            io.went(
                peer,
                &format!("{} (RTU, unit {})", describe_request(&pdu), self.unit),
            );
            io.send(Target::Default, encode_rtu(self.unit, &pdu));
        } else {
            io.went(
                peer,
                &format!(
                    "{} (transaction {}, unit {})",
                    describe_request(&pdu),
                    self.transaction,
                    self.unit
                ),
            );
            io.send(Target::Default, frame.encode());
        }
        self.asked.insert(self.transaction, (pdu, Instant::now()));
    }

    /// The request a command line makes.
    fn request(words: &mut Words) -> Result<Vec<u8>, String> {
        let command = words.next().unwrap_or_default().to_lowercase();
        let read = |function: u8, most: u16, words: &mut Words| -> Result<Vec<u8>, String> {
            let start: u16 = words.number("the first address")?;
            let count: u16 = words.number_or("how many", 1)?;
            if count == 0 || count > most {
                return Err(format!("One request reads 1 to {most} of them."));
            }
            let mut pdu = vec![function];
            pdu.extend_from_slice(&start.to_be_bytes());
            pdu.extend_from_slice(&count.to_be_bytes());
            Ok(pdu)
        };
        match command.as_str() {
            "coils" | "rc" => read(READ_COILS, 2000, words),
            "discrete" | "di" | "rd" => read(READ_DISCRETE, 2000, words),
            "holding" | "hr" | "rh" => read(READ_HOLDING, 125, words),
            "inputs" | "ir" | "ri" => read(READ_INPUT, 125, words),
            "coil" | "wc" => {
                let address: u16 = words.number("the coil's address")?;
                let on = on_off(&words.need("on or off")?)?;
                let mut pdu = vec![WRITE_COIL];
                pdu.extend_from_slice(&address.to_be_bytes());
                pdu.extend_from_slice(if on { &[0xFF, 0x00] } else { &[0x00, 0x00] });
                Ok(pdu)
            }
            "register" | "wr" => {
                let address: u16 = words.number("the register's address")?;
                let value = register_value(&words.need("the value")?)?;
                let mut pdu = vec![WRITE_REGISTER];
                pdu.extend_from_slice(&address.to_be_bytes());
                pdu.extend_from_slice(&value.to_be_bytes());
                Ok(pdu)
            }
            "write-coils" | "wcs" => {
                let start: u16 = words.number("the first coil's address")?;
                let mut values = Vec::new();
                while let Some(word) = words.next() {
                    values.push(on_off(&word)?);
                }
                if values.is_empty() || values.len() > 1968 {
                    return Err("Give 1 to 1968 values: 1 or 0, on or off.".into());
                }
                let mut pdu = vec![WRITE_COILS];
                pdu.extend_from_slice(&start.to_be_bytes());
                pdu.extend_from_slice(&(values.len() as u16).to_be_bytes());
                let bytes = pack_bits(&values);
                pdu.push(bytes.len() as u8);
                pdu.extend_from_slice(&bytes);
                Ok(pdu)
            }
            "write-registers" | "wrs" => {
                let start: u16 = words.number("the first register's address")?;
                let mut values = Vec::new();
                while let Some(word) = words.next() {
                    values.push(register_value(&word)?);
                }
                if values.is_empty() || values.len() > 123 {
                    return Err("Give 1 to 123 values.".into());
                }
                let mut pdu = vec![WRITE_REGISTERS];
                pdu.extend_from_slice(&start.to_be_bytes());
                pdu.extend_from_slice(&(values.len() as u16).to_be_bytes());
                pdu.push((values.len() * 2) as u8);
                for value in values {
                    pdu.extend_from_slice(&value.to_be_bytes());
                }
                Ok(pdu)
            }
            "raw" => {
                let bytes = super::words::unescape(&words.rest_text());
                let hex: String = String::from_utf8_lossy(&bytes).split_whitespace().collect();
                let pdu = (0..hex.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(hex.get(at..at + 2).unwrap_or("x"), 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|_| {
                        "raw takes the PDU in hex: the function and its data, such as 03 0000 000a."
                            .to_string()
                    })?;
                if pdu.is_empty() {
                    return Err("raw takes the PDU in hex, such as 03 0000 000a.".into());
                }
                Ok(pdu)
            }
            other => Err(format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }
}

fn on_off(word: &str) -> Result<bool, String> {
    match word.to_lowercase().as_str() {
        "1" | "on" | "true" => Ok(true),
        "0" | "off" | "false" => Ok(false),
        other => Err(format!("{other} is not on or off.")),
    }
}

/// A register's value: 0 to 65535, or a negative number as its two's complement.
fn register_value(word: &str) -> Result<u16, String> {
    super::words::parse_number::<i32>(word)
        .filter(|value| (-32768..=65535).contains(value))
        .map(|value| value as u16)
        .ok_or_else(|| format!("{word} is not a register's value: -32768 to 65535."))
}

const MASTER_HELP: &str = "coils <start> [count]               read coils (1)
discrete <start> [count]            read discrete inputs (2)
holding <start> [count]             read holding registers (3)
inputs <start> [count]              read input registers (4)
coil <address> on|off               write a coil (5)
register <address> <value>          write a register (6)
write-coils <start> <1|0>...        write coils (15)
write-registers <start> <value>...  write registers (16)
raw <pdu in hex>                    any request, such as raw 03 0000 000a
unit <id>                           the unit id requests go to
poll <ms> <command>                 a read again and again, such as poll 500 holding 0 4
stop                                stop polling
Numbers may be hex: 0x10.";

impl Engine for Master {
    fn help(&self) -> &'static str {
        MASTER_HELP
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        self.peer = Some(peer.id);
        self.buffer.clear();
        self.asked.clear();
    }

    fn left(&mut self, _peer: PeerId, _io: &mut Io) {
        self.peer = None;
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.buffer.extend_from_slice(bytes);
        loop {
            let taken = if self.rtu {
                take_rtu(&mut self.buffer, true)
            } else {
                take(&mut self.buffer)
            };
            match taken {
                Ok(Some(frame)) => {
                    // RTU has no transaction: answers come in the order asked.
                    let key = if self.rtu {
                        self.asked.keys().next().copied().unwrap_or(0)
                    } else {
                        frame.transaction
                    };
                    let asked = self.asked.remove(&key);
                    let late = asked
                        .as_ref()
                        .map(|(_, sent)| format!(", {} ms", sent.elapsed().as_millis()))
                        .unwrap_or_else(|| ", not asked for".into());
                    io.came(
                        peer,
                        &format!(
                            "{} (transaction {}, unit {}{late})",
                            describe_answer(
                                &frame.pdu,
                                asked.as_ref().map(|(pdu, _)| pdu.as_slice())
                            ),
                            frame.transaction,
                            frame.unit
                        ),
                    );
                }
                Ok(None) => break,
                Err(problem) => {
                    io.bad(&format!(
                        "What came is not Modbus TCP: {problem}: {}",
                        hex_text(&self.buffer)
                    ));
                    self.buffer.clear();
                    break;
                }
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.peek().as_deref() {
                Some("unit") => {
                    words.next();
                    self.unit = words.number("the unit id: 0 to 255")?;
                    io.note(&format!("Requests go to unit {} now.", self.unit));
                    Ok(())
                }
                Some("poll") => {
                    words.next();
                    let every: u64 = words.number("how often, in ms")?;
                    let line = words.rest_text();
                    Self::request(&mut Words::new(&line))?;
                    self.poll = Some(Poll {
                        line,
                        every: Duration::from_millis(every.max(50)),
                        next: Instant::now(),
                    });
                    Ok(())
                }
                Some("stop") => {
                    self.poll = None;
                    io.note("Polling stopped.");
                    Ok(())
                }
                _ => {
                    let pdu = Self::request(words)?;
                    self.ask(pdu, io);
                    Ok(())
                }
            }
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        let late: Vec<u16> = self
            .asked
            .iter()
            .filter(|(_, (_, sent))| now.duration_since(*sent) >= ANSWER_TIME)
            .map(|(transaction, _)| *transaction)
            .collect();
        for transaction in late {
            self.asked.remove(&transaction);
            io.bad(&format!(
                "No answer to transaction {transaction} in {} s: is unit {} there?",
                ANSWER_TIME.as_secs(),
                self.unit
            ));
        }
        let due = self.poll.as_ref().is_some_and(|poll| now >= poll.next);
        if due && self.peer.is_some() {
            let line = self
                .poll
                .as_ref()
                .map(|poll| poll.line.clone())
                .unwrap_or_default();
            if let Ok(pdu) = Self::request(&mut Words::new(&line)) {
                self.ask(pdu, io);
            }
            if let Some(poll) = &mut self.poll {
                poll.next = now + poll.every;
            }
        }
    }
}

// ----- The slave -----

/// A Modbus TCP slave tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SlaveOptions {
    /// The unit id it answers; 0 for any.
    pub unit: u8,
    /// RTU frames with a CRC, rather than MBAP headers: Modbus RTU over TCP.
    pub rtu: bool,
}

pub struct Slave {
    unit: u8,
    rtu: bool,
    coils: Vec<bool>,
    discrete: Vec<bool>,
    holding: Vec<u16>,
    input: Vec<u16>,
    buffers: BTreeMap<PeerId, Vec<u8>>,
    /// Answers every request with this exception, to test a master.
    exception: Option<u8>,
    /// Registers that count up by one each second, for a plot.
    counting: Vec<(char, u16)>,
    counted: Instant,
}

impl Slave {
    pub fn new(options: SlaveOptions) -> Self {
        Self {
            unit: options.unit,
            rtu: options.rtu,
            coils: vec![false; 65536],
            discrete: vec![false; 65536],
            holding: vec![0; 65536],
            input: vec![0; 65536],
            buffers: BTreeMap::new(),
            exception: None,
            counting: Vec::new(),
            counted: Instant::now(),
        }
    }

    /// The answer to a request's PDU.
    fn answer(&mut self, pdu: &[u8]) -> Vec<u8> {
        let function = pdu.first().copied().unwrap_or(0);
        if let Some(code) = self.exception {
            return vec![function | 0x80, code];
        }
        match self.serve(pdu) {
            Ok(answer) => answer,
            Err(code) => vec![function | 0x80, code],
        }
    }

    fn serve(&mut self, pdu: &[u8]) -> Result<Vec<u8>, u8> {
        let function = *pdu.first().ok_or(1u8)?;
        const KNOWN: [u8; 9] = [
            READ_COILS,
            READ_DISCRETE,
            READ_HOLDING,
            READ_INPUT,
            WRITE_COIL,
            WRITE_REGISTER,
            WRITE_COILS,
            WRITE_REGISTERS,
            READ_WRITE_REGISTERS,
        ];
        if !KNOWN.contains(&function) {
            return Err(1);
        }
        let start = usize::from(word(pdu, 1).ok_or(3u8)?);
        let count = usize::from(word(pdu, 3).ok_or(3u8)?);
        let range = |most: usize| -> Result<std::ops::Range<usize>, u8> {
            if count == 0 || count > most {
                return Err(3);
            }
            if start + count > 65536 {
                return Err(2);
            }
            Ok(start..start + count)
        };
        match function {
            READ_COILS | READ_DISCRETE => {
                let range = range(2000)?;
                let table = if function == READ_COILS {
                    &self.coils
                } else {
                    &self.discrete
                };
                let bytes = pack_bits(&table[range]);
                Ok([vec![function, bytes.len() as u8], bytes].concat())
            }
            READ_HOLDING | READ_INPUT => {
                let range = range(125)?;
                let table = if function == READ_HOLDING {
                    &self.holding
                } else {
                    &self.input
                };
                let mut answer = vec![function, (count * 2) as u8];
                for value in &table[range] {
                    answer.extend_from_slice(&value.to_be_bytes());
                }
                Ok(answer)
            }
            WRITE_COIL => {
                let value = word(pdu, 3).ok_or(3u8)?;
                if value != 0xFF00 && value != 0 {
                    return Err(3);
                }
                self.coils[start] = value == 0xFF00;
                Ok(pdu[..5].to_vec())
            }
            WRITE_REGISTER => {
                self.holding[start] = word(pdu, 3).ok_or(3u8)?;
                Ok(pdu[..5].to_vec())
            }
            WRITE_COILS => {
                let range = range(1968)?;
                let bytes = pdu.get(6..6 + count.div_ceil(8)).ok_or(3u8)?;
                let values = unpack_bits(bytes, count);
                self.coils[range].copy_from_slice(&values);
                Ok(pdu[..5].to_vec())
            }
            WRITE_REGISTERS => {
                let range = range(123)?;
                for (index, address) in range.enumerate() {
                    self.holding[address] = word(pdu, 6 + index * 2).ok_or(3u8)?;
                }
                Ok(pdu[..5].to_vec())
            }
            READ_WRITE_REGISTERS => {
                let read = range(125)?;
                let write_start = usize::from(word(pdu, 5).ok_or(3u8)?);
                let write_count = usize::from(word(pdu, 7).ok_or(3u8)?);
                if write_count == 0 || write_count > 121 || write_start + write_count > 65536 {
                    return Err(3);
                }
                for index in 0..write_count {
                    self.holding[write_start + index] = word(pdu, 10 + index * 2).ok_or(3u8)?;
                }
                let mut answer = vec![function, (count * 2) as u8];
                for value in &self.holding[read] {
                    answer.extend_from_slice(&value.to_be_bytes());
                }
                Ok(answer)
            }
            _ => Err(1),
        }
    }

    fn table_of(word: &str) -> Result<char, String> {
        match word.to_lowercase().as_str() {
            "coil" | "coils" => Ok('c'),
            "discrete" | "di" => Ok('d'),
            "holding" | "hr" | "register" | "registers" => Ok('h'),
            "input" | "inputs" | "ir" => Ok('i'),
            other => Err(format!(
                "{other} is not a table: coils, discrete, holding or inputs."
            )),
        }
    }
}

const SLAVE_HELP: &str =
    "set <table> <address> <value>...   set values; tables: coils, discrete, holding, inputs
show <table> <address> [count]     show values
count <table> <address>            a register that counts up each second, to plot; again to stop
exception <code>|off               answer every request with this exception, such as 6 for busy
unit <id>                          the unit id it answers; 0 for any";

impl Engine for Slave {
    fn help(&self) -> &'static str {
        SLAVE_HELP
    }

    fn left(&mut self, peer: PeerId, _io: &mut Io) {
        self.buffers.remove(&peer);
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let buffer = self.buffers.entry(peer).or_default();
        buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        let rtu = self.rtu;
        loop {
            let taken = if rtu {
                take_rtu(buffer, false)
            } else {
                take(buffer)
            };
            match taken {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break,
                Err(problem) => {
                    io.bad(&format!(
                        "What came is not Modbus TCP: {problem}: {}",
                        hex_text(buffer)
                    ));
                    buffer.clear();
                    break;
                }
            }
        }
        for frame in frames {
            io.came(
                peer,
                &format!(
                    "{} (transaction {}, unit {})",
                    describe_request(&frame.pdu),
                    frame.transaction,
                    frame.unit
                ),
            );
            if self.unit != 0 && frame.unit != self.unit {
                io.note(&format!(
                    "Unit {} is not this slave's {}: no answer.",
                    frame.unit, self.unit
                ));
                continue;
            }
            let answer = self.answer(&frame.pdu);
            io.went(
                peer,
                &format!(
                    "{} (transaction {})",
                    describe_answer(&answer, Some(&frame.pdu)),
                    frame.transaction
                ),
            );
            let bytes = if self.rtu {
                encode_rtu(frame.unit, &answer)
            } else {
                Frame {
                    transaction: frame.transaction,
                    unit: frame.unit,
                    pdu: answer,
                }
                .encode()
            };
            io.send(Target::Peer(peer), bytes);
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            let command = words.next().unwrap_or_default().to_lowercase();
            match command.as_str() {
                "set" => {
                    let table = Self::table_of(&words.need("the table")?)?;
                    let start: u16 = words.number("the address")?;
                    let mut count = 0usize;
                    while let Some(value) = words.next() {
                        let address = usize::from(start) + count;
                        if address > 65535 {
                            return Err("The addresses end at 65535.".into());
                        }
                        match table {
                            'c' => self.coils[address] = on_off(&value)?,
                            'd' => self.discrete[address] = on_off(&value)?,
                            'h' => self.holding[address] = register_value(&value)?,
                            _ => self.input[address] = register_value(&value)?,
                        }
                        count += 1;
                    }
                    if count == 0 {
                        return Err("Missing: the values.".into());
                    }
                    io.note(&format!("{count} values set from {start}."));
                }
                "show" => {
                    let table = Self::table_of(&words.need("the table")?)?;
                    let start: u16 = words.number("the address")?;
                    let count: u16 = words.number_or("how many", 10)?;
                    let end = (usize::from(start) + usize::from(count)).min(65536);
                    let range = usize::from(start)..end;
                    let text = match table {
                        'c' => bits_text(start, &self.coils[range]),
                        'd' => bits_text(start, &self.discrete[range]),
                        'h' => registers_text(start, &self.holding[range]),
                        _ => registers_text(start, &self.input[range]),
                    };
                    io.note(&text);
                }
                "count" => {
                    let table = Self::table_of(&words.need("the table: holding or inputs")?)?;
                    if table != 'h' && table != 'i' {
                        return Err("Only registers count: holding or inputs.".into());
                    }
                    let address: u16 = words.number("the address")?;
                    if let Some(at) = self
                        .counting
                        .iter()
                        .position(|item| *item == (table, address))
                    {
                        self.counting.remove(at);
                        io.note(&format!("{address} counts no more."));
                    } else {
                        self.counting.push((table, address));
                        io.note(&format!("{address} counts up by one each second."));
                    }
                }
                "exception" => {
                    let word = words.need("an exception code, or off")?;
                    self.exception = if word.eq_ignore_ascii_case("off") {
                        None
                    } else {
                        Some(
                            super::words::parse_number(&word)
                                .ok_or(format!("{word} is not an exception code."))?,
                        )
                    };
                    match self.exception {
                        Some(code) => io.note(&format!(
                            "Every request is answered with exception {code}, {}.",
                            exception_name(code)
                        )),
                        None => io.note("Requests are answered again."),
                    }
                }
                "unit" => {
                    self.unit = words.number("the unit id")?;
                    io.note(&format!(
                        "It answers unit {} now.",
                        if self.unit == 0 {
                            "any".into()
                        } else {
                            self.unit.to_string()
                        }
                    ));
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

    fn tick(&mut self, now: Instant, _io: &mut Io) {
        if now.duration_since(self.counted) < Duration::from_secs(1) {
            return;
        }
        self.counted = now;
        for (table, address) in &self.counting {
            let cell = if *table == 'h' {
                &mut self.holding[usize::from(*address)]
            } else {
                &mut self.input[usize::from(*address)]
            };
            *cell = cell.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{client_to, listening, server_on_loopback, shown, start};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn frames_are_cut_from_a_stream() {
        let frame = Frame {
            transaction: 7,
            unit: 1,
            pdu: vec![3, 0, 0, 0, 10],
        };
        let mut bytes = frame.encode();
        assert_eq!(bytes, [0, 7, 0, 0, 0, 6, 1, 3, 0, 0, 0, 10]);
        bytes.extend_from_slice(&[0, 8, 0, 0]);
        assert_eq!(take(&mut bytes).unwrap(), Some(frame));
        assert_eq!(take(&mut bytes).unwrap(), None);
        let mut wrong = vec![0, 1, 0, 9, 0, 6, 1, 3, 0, 0, 0, 1];
        assert!(take(&mut wrong).is_err());
    }

    #[test]
    fn rtu_frames_have_their_crc_and_are_cut_by_their_function() {
        // The usual example: unit 1, read 2 holding registers from 0.
        let frame = encode_rtu(1, &[READ_HOLDING, 0, 0, 0, 2]);
        assert_eq!(frame, [0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0xc4, 0x0b]);
        let mut stream = frame.clone();
        stream.extend_from_slice(&encode_rtu(1, &[READ_HOLDING, 4, 0, 1, 0, 2]));
        let request = take_rtu(&mut stream, false).unwrap().unwrap();
        assert_eq!(request.pdu, [READ_HOLDING, 0, 0, 0, 2]);
        let answer = take_rtu(&mut stream, true).unwrap().unwrap();
        assert_eq!(answer.pdu, [READ_HOLDING, 4, 0, 1, 0, 2]);
        let mut broken = frame;
        broken[7] ^= 1;
        assert!(take_rtu(&mut broken, false).unwrap_err().contains("CRC"));
    }

    #[test]
    fn a_master_and_a_slave_speak_rtu_over_tcp() {
        let (slave, slave_events) = start(
            Box::new(Slave::new(SlaveOptions { unit: 0, rtu: true })),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&slave_events);
        let (master, master_events) = start(
            Box::new(Master::new(MasterOptions { unit: 3, rtu: true })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        crate::net::tests::joined(&master_events);
        slave.command("set inputs 0 42 43");
        master.command("inputs 0 2");
        shown(&master_events, "0=42 (0x002a)  1=43 (0x002b)");
        master.command("write-registers 5 7 8");
        shown(&master_events, "5 to 6 written");
        master.command("coils 0 3");
        shown(&master_events, "0=0 1=0 2=0");
    }

    #[test]
    fn the_slave_answers_reads_writes_and_bad_requests() {
        let mut slave = Slave::new(SlaveOptions::default());
        assert_eq!(
            slave.answer(&[WRITE_REGISTER, 0, 5, 0x04, 0xd2]),
            [WRITE_REGISTER, 0, 5, 0x04, 0xd2]
        );
        assert_eq!(
            slave.answer(&[READ_HOLDING, 0, 4, 0, 2]),
            [READ_HOLDING, 4, 0, 0, 0x04, 0xd2]
        );
        assert_eq!(
            slave.answer(&[WRITE_COILS, 0, 0, 0, 3, 1, 0b101]),
            [WRITE_COILS, 0, 0, 0, 3]
        );
        assert_eq!(
            slave.answer(&[READ_COILS, 0, 0, 0, 3]),
            [READ_COILS, 1, 0b101]
        );
        assert_eq!(slave.answer(&[READ_HOLDING, 0, 0, 0, 200]), [0x83, 3]);
        assert_eq!(slave.answer(&[READ_HOLDING, 0xff, 0xff, 0, 2]), [0x83, 2]);
        assert_eq!(slave.answer(&[0x42]), [0xc2, 1]);
        assert_eq!(
            describe_answer(&[0x83, 2], None),
            "Read Holding Registers: exception 2, Illegal Data Address"
        );
    }

    #[test]
    fn a_master_reads_and_writes_a_slave() {
        let (slave, slave_events) = start(
            Box::new(Slave::new(SlaveOptions::default())),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&slave_events);
        let (master, master_events) = start(
            Box::new(Master::new(MasterOptions {
                unit: 1,
                rtu: false,
            })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        crate::net::tests::joined(&master_events);
        slave.command("set holding 10 1234 -1");
        master.command("holding 10 2");
        shown(&master_events, "10=1234 (0x04d2)  11=65535 (0xffff)");
        master.command("coil 3 on");
        shown(&master_events, "Write Single Coil 3 = on: done");
        master.command("coils 0 4");
        shown(&master_events, "0=0 1=0 2=0 3=1");
        master.command("write-registers 0x20 1 2 3");
        shown(&master_events, "32 to 34 written");
        slave.command("exception 6");
        master.command("inputs 0");
        shown(&master_events, "exception 6, Server Device Busy");
        slave.command("exception off");
        master.command("raw 04 0000 0001");
        shown(&master_events, "Read Input Registers: 0=0");
        master.command("frobnicate");
        shown(&master_events, "frobnicate is not a command here");
    }
}
