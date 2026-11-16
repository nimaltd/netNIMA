//! A small CBOR (RFC 8949) codec: the values SMP, LwM2M and SenML carry,
//! and a way to show them, as CBOR's diagnostic notation does.

/// One CBOR value.
#[derive(Clone, Debug, PartialEq)]
pub enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
    Float(f64),
}

impl Cbor {
    /// A map's value for a text key.
    pub fn get(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(found, _)| matches!(found, Cbor::Text(text) if text == key))
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Cbor::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// A map with text keys, in the order given.
    pub fn map(entries: Vec<(&str, Cbor)>) -> Cbor {
        Cbor::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Cbor::Text(key.into()), value))
                .collect(),
        )
    }

    /// The value as JSON, for the views: bytes as hex digits, a map with
    /// keys that are not text as its keys' CBOR text, and a float that JSON
    /// cannot hold (NaN, the infinities) as null.
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value as Json;
        match self {
            Cbor::Int(value) => match i64::try_from(*value) {
                Ok(small) => Json::from(small),
                Err(_) => match u64::try_from(*value) {
                    Ok(big) => Json::from(big),
                    Err(_) => Json::String(value.to_string()),
                },
            },
            Cbor::Bytes(bytes) => Json::String(super::hex(bytes)),
            Cbor::Text(text) => Json::String(text.clone()),
            Cbor::Array(items) => Json::Array(items.iter().map(Cbor::to_json).collect()),
            Cbor::Map(entries) => Json::Object(
                entries
                    .iter()
                    .map(|(key, value)| {
                        let key = match key {
                            Cbor::Text(text) => text.clone(),
                            other => other.to_string(),
                        };
                        (key, value.to_json())
                    })
                    .collect(),
            ),
            Cbor::Bool(value) => Json::Bool(*value),
            Cbor::Null => Json::Null,
            Cbor::Float(value) => {
                serde_json::Number::from_f64(*value).map_or(Json::Null, Json::Number)
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Int(value) if *value >= 0 => head(out, 0, *value as u64),
            Cbor::Int(value) => head(out, 1, (-1 - *value) as u64),
            Cbor::Bytes(bytes) => {
                head(out, 2, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Cbor::Text(text) => {
                head(out, 3, text.len() as u64);
                out.extend_from_slice(text.as_bytes());
            }
            Cbor::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.write(out);
                }
            }
            Cbor::Map(entries) => {
                head(out, 5, entries.len() as u64);
                for (key, value) in entries {
                    key.write(out);
                    value.write(out);
                }
            }
            Cbor::Bool(false) => out.push(0xf4),
            Cbor::Bool(true) => out.push(0xf5),
            Cbor::Null => out.push(0xf6),
            Cbor::Float(value) => {
                out.push(0xfb);
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
    }

    /// The first value in `bytes`, and how many bytes it took.
    pub fn decode(bytes: &[u8]) -> Result<(Cbor, usize), String> {
        let mut at = 0;
        let value = read(bytes, &mut at, 0)?;
        Ok((value, at))
    }
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

const BREAK: u8 = 0xff;

fn take<'a>(bytes: &'a [u8], at: &mut usize, count: usize) -> Result<&'a [u8], String> {
    let taken = bytes
        .get(*at..*at + count)
        .ok_or("the CBOR ends too soon")?;
    *at += count;
    Ok(taken)
}

/// The argument of a head: its number, or None for "indefinite length".
fn argument(bytes: &[u8], at: &mut usize, info: u8) -> Result<Option<u64>, String> {
    Ok(Some(match info {
        0..=23 => u64::from(info),
        24 => u64::from(take(bytes, at, 1)?[0]),
        25 => u64::from(u16::from_be_bytes(
            take(bytes, at, 2)?.try_into().unwrap_or_default(),
        )),
        26 => u64::from(u32::from_be_bytes(
            take(bytes, at, 4)?.try_into().unwrap_or_default(),
        )),
        27 => u64::from_be_bytes(take(bytes, at, 8)?.try_into().unwrap_or_default()),
        31 => return Ok(None),
        _ => return Err(format!("a CBOR head has the reserved value {info}")),
    }))
}

fn read(bytes: &[u8], at: &mut usize, depth: usize) -> Result<Cbor, String> {
    if depth > 64 {
        return Err("the CBOR nests deeper than netNIMA follows".into());
    }
    let first = take(bytes, at, 1)?[0];
    let major = first >> 5;
    let info = first & 0x1f;
    match major {
        0 | 1 => {
            let value = argument(bytes, at, info)?.ok_or("an integer has no length")?;
            Ok(Cbor::Int(if major == 0 {
                i128::from(value)
            } else {
                -1 - i128::from(value)
            }))
        }
        2 | 3 => {
            let data = match argument(bytes, at, info)? {
                Some(length) => take(bytes, at, length as usize)?.to_vec(),
                None => {
                    // Indefinite length: chunks until the break.
                    let mut data = Vec::new();
                    while bytes.get(*at) != Some(&BREAK) {
                        match read(bytes, at, depth + 1)? {
                            Cbor::Bytes(chunk) => data.extend(chunk),
                            Cbor::Text(chunk) => data.extend(chunk.into_bytes()),
                            _ => return Err("a string's chunk is not a string".into()),
                        }
                    }
                    *at += 1;
                    data
                }
            };
            if major == 2 {
                Ok(Cbor::Bytes(data))
            } else {
                String::from_utf8(data)
                    .map(Cbor::Text)
                    .map_err(|_| "a CBOR text is not UTF-8".into())
            }
        }
        4 => {
            let mut items = Vec::new();
            match argument(bytes, at, info)? {
                Some(count) => {
                    for _ in 0..count {
                        items.push(read(bytes, at, depth + 1)?);
                    }
                }
                None => {
                    while bytes.get(*at) != Some(&BREAK) {
                        items.push(read(bytes, at, depth + 1)?);
                    }
                    *at += 1;
                }
            }
            Ok(Cbor::Array(items))
        }
        5 => {
            let mut entries = Vec::new();
            match argument(bytes, at, info)? {
                Some(count) => {
                    for _ in 0..count {
                        let key = read(bytes, at, depth + 1)?;
                        entries.push((key, read(bytes, at, depth + 1)?));
                    }
                }
                None => {
                    while bytes.get(*at) != Some(&BREAK) {
                        let key = read(bytes, at, depth + 1)?;
                        entries.push((key, read(bytes, at, depth + 1)?));
                    }
                    *at += 1;
                }
            }
            Ok(Cbor::Map(entries))
        }
        // A tag: the value it tags.
        6 => {
            argument(bytes, at, info)?;
            read(bytes, at, depth + 1)
        }
        _ => match info {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 | 23 => Ok(Cbor::Null),
            25 => Ok(Cbor::Float(half(u16::from_be_bytes(
                take(bytes, at, 2)?.try_into().unwrap_or_default(),
            )))),
            26 => Ok(Cbor::Float(f64::from(f32::from_be_bytes(
                take(bytes, at, 4)?.try_into().unwrap_or_default(),
            )))),
            27 => Ok(Cbor::Float(f64::from_be_bytes(
                take(bytes, at, 8)?.try_into().unwrap_or_default(),
            ))),
            other => Err(format!(
                "CBOR's simple value {other} is not one netNIMA reads"
            )),
        },
    }
}

/// A half-precision float's value.
fn half(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from((bits >> 10) & 0x1f);
    let fraction = f64::from(bits & 0x3ff);
    match exponent {
        0 => sign * fraction * 2f64.powi(-24),
        31 => {
            if fraction == 0.0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => sign * (1.0 + fraction / 1024.0) * 2f64.powi(exponent - 15),
    }
}

impl std::fmt::Display for Cbor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cbor::Int(value) => write!(formatter, "{value}"),
            Cbor::Bytes(bytes) => {
                write!(formatter, "h'")?;
                for byte in bytes.iter().take(48) {
                    write!(formatter, "{byte:02x}")?;
                }
                if bytes.len() > 48 {
                    write!(formatter, "...({} bytes)", bytes.len())?;
                }
                write!(formatter, "'")
            }
            Cbor::Text(text) => write!(formatter, "{text:?}"),
            Cbor::Array(items) => {
                write!(formatter, "[")?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        write!(formatter, ", ")?;
                    }
                    write!(formatter, "{item}")?;
                }
                write!(formatter, "]")
            }
            Cbor::Map(entries) => {
                write!(formatter, "{{")?;
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        write!(formatter, ", ")?;
                    }
                    write!(formatter, "{key}: {value}")?;
                }
                write!(formatter, "}}")
            }
            Cbor::Bool(value) => write!(formatter, "{value}"),
            Cbor::Null => write!(formatter, "null"),
            Cbor::Float(value) => write!(formatter, "{value}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_read_back_as_they_were_written() {
        let value = Cbor::map(vec![
            ("off", Cbor::Int(70_000)),
            ("rc", Cbor::Int(-5)),
            ("data", Cbor::Bytes(vec![1, 2, 3])),
            ("name", Cbor::Text("main".into())),
            (
                "list",
                Cbor::Array(vec![Cbor::Bool(true), Cbor::Null, Cbor::Float(21.5)]),
            ),
        ]);
        let bytes = value.encode();
        assert_eq!(Cbor::decode(&bytes).unwrap(), (value.clone(), bytes.len()));
        assert_eq!(value.get("off").and_then(Cbor::as_int), Some(70_000));
        assert_eq!(
            value.to_string(),
            r#"{"off": 70000, "rc": -5, "data": h'010203', "name": "main", "list": [true, null, 21.5]}"#
        );
    }

    #[test]
    fn indefinite_lengths_halves_and_tags_are_read() {
        // {_ "a": [_ 1, 2], "b": 1.5 (half)}
        let bytes = [
            0xbf, 0x61, b'a', 0x9f, 0x01, 0x02, 0xff, 0x61, b'b', 0xf9, 0x3e, 0x00, 0xff,
        ];
        let (value, used) = Cbor::decode(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(value.to_string(), r#"{"a": [1, 2], "b": 1.5}"#);
        // Tag 1 (a time) around 1000.
        assert_eq!(
            Cbor::decode(&[0xc1, 0x19, 0x03, 0xe8]).unwrap().0,
            Cbor::Int(1000)
        );
        assert!(Cbor::decode(&[0x62, b'a']).is_err());
    }

    #[test]
    fn values_turn_into_json_for_the_views() {
        let value = Cbor::Map(vec![
            (Cbor::Text("rc".into()), Cbor::Int(-5)),
            (Cbor::Text("hash".into()), Cbor::Bytes(vec![0xab, 0x01])),
            (
                Cbor::Int(7),
                Cbor::Array(vec![Cbor::Bool(true), Cbor::Null]),
            ),
            (Cbor::Text("t".into()), Cbor::Float(21.5)),
            (Cbor::Text("nan".into()), Cbor::Float(f64::NAN)),
            (Cbor::Text("big".into()), Cbor::Int(-(1i128 << 64))),
        ]);
        assert_eq!(
            value.to_json(),
            serde_json::json!({
                "rc": -5,
                "hash": "ab01",
                "7": [true, null],
                "t": 21.5,
                "nan": null,
                "big": "-18446744073709551616",
            })
        );
    }
}
