//! Reading a command typed in the send box, word by word, and showing
//! payloads as people read them.

/// A typed command, read a word at a time. A word in double quotes may hold
/// spaces; `rest` takes the rest of the line as it was typed, for payloads.
pub struct Words {
    line: String,
    at: usize,
}

impl Words {
    pub fn new(line: &str) -> Self {
        Self {
            line: line.trim().to_string(),
            at: 0,
        }
    }

    fn skip_spaces(&mut self) {
        while self.line[self.at..].starts_with(char::is_whitespace) {
            self.at += self.line[self.at..]
                .chars()
                .next()
                .map_or(1, char::len_utf8);
        }
    }

    /// The next word, without taking it, in lower case: for choosing a command.
    pub fn peek(&mut self) -> Option<String> {
        let at = self.at;
        let word = self.next();
        self.at = at;
        word.map(|word| word.to_lowercase())
    }

    /// The next word, or None at the end of the line.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<String> {
        self.skip_spaces();
        let rest = &self.line[self.at..];
        if rest.is_empty() {
            return None;
        }
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut word = String::new();
            let mut chars = quoted.char_indices();
            let mut end = quoted.len();
            while let Some((index, c)) = chars.next() {
                match c {
                    '"' => {
                        end = index + 1;
                        break;
                    }
                    '\\' => match chars.next() {
                        Some((_, 'n')) => word.push('\n'),
                        Some((_, 'r')) => word.push('\r'),
                        Some((_, 't')) => word.push('\t'),
                        Some((_, other)) => word.push(other),
                        None => {}
                    },
                    other => word.push(other),
                }
            }
            self.at += 1 + end;
            return Some(word);
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        self.at += end;
        Some(rest[..end].to_string())
    }

    /// The next word, which must be there: `what` names it in the problem.
    pub fn need(&mut self, what: &str) -> Result<String, String> {
        self.next().ok_or_else(|| format!("Missing: {what}."))
    }

    /// The next word as a number, which must be there.
    pub fn number<T: std::str::FromStr>(&mut self, what: &str) -> Result<T, String> {
        let word = self.need(what)?;
        parse_number(&word).ok_or_else(|| format!("{word} is not a number for {what}."))
    }

    /// The next word as a number, or `default` at the end of the line.
    pub fn number_or<T: std::str::FromStr>(&mut self, what: &str, default: T) -> Result<T, String> {
        match self.next() {
            None => Ok(default),
            Some(word) => {
                parse_number(&word).ok_or_else(|| format!("{word} is not a number for {what}."))
            }
        }
    }

    /// Flags before the other words, such as `-q1 -r`: each with what follows
    /// its letter. Taken off the line.
    pub fn flags(&mut self) -> Vec<(char, String)> {
        let mut found = Vec::new();
        loop {
            self.skip_spaces();
            let rest = &self.line[self.at..];
            let Some(flag) = rest.strip_prefix('-') else {
                break;
            };
            let mut chars = flag.chars();
            let Some(letter) = chars.next().filter(char::is_ascii_alphabetic) else {
                break;
            };
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let value = rest[2..end].to_string();
            self.at += end;
            found.push((letter, value));
        }
        found
    }

    /// The rest of the line as typed, from the next word on; empty at the end.
    /// Escapes such as `\r\n` and `\x00` are turned into their bytes.
    pub fn rest(&mut self) -> Vec<u8> {
        self.skip_spaces();
        let rest = self.line[self.at..].to_string();
        self.at = self.line.len();
        unescape(&rest)
    }

    /// The rest of the line as text, as typed.
    pub fn rest_text(&mut self) -> String {
        self.skip_spaces();
        let rest = self.line[self.at..].to_string();
        self.at = self.line.len();
        rest
    }

    /// Whether every word has been read.
    pub fn done(&mut self) -> bool {
        self.skip_spaces();
        self.at >= self.line.len()
    }
}

/// A number written as people do: 1234, 0x4D2 or 0b101.
pub fn parse_number<T: std::str::FromStr>(word: &str) -> Option<T> {
    let word = word.trim().replace('_', "");
    let value: i128 = if let Some(hex) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16).ok()?
    } else if let Some(binary) = word.strip_prefix("0b") {
        i128::from_str_radix(binary, 2).ok()?
    } else {
        return word.parse().ok();
    };
    value.to_string().parse().ok()
}

/// Text with `\r`, `\n`, `\t`, `\\` and `\xHH` turned into their bytes.
pub fn unescape(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 1 < bytes.len() {
            let next = bytes[index + 1];
            let simple = match next {
                b'r' => Some(b'\r'),
                b'n' => Some(b'\n'),
                b't' => Some(b'\t'),
                b'0' => Some(0),
                b'\\' => Some(b'\\'),
                _ => None,
            };
            if let Some(byte) = simple {
                out.push(byte);
                index += 2;
                continue;
            }
            if next == b'x'
                && index + 3 < bytes.len() + 1
                && let Some(hex) = text.get(index + 2..index + 4)
                && let Ok(byte) = u8::from_str_radix(hex, 16)
            {
                out.push(byte);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// A payload as people read it: text when it is text, with control
/// characters written as escapes, or hex when it is not.
pub fn payload_text(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".into();
    }
    match std::str::from_utf8(bytes) {
        Ok(text)
            if text
                .chars()
                .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') =>
        {
            let mut out = String::with_capacity(text.len());
            for c in text.chars() {
                match c {
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\n' => out.push_str("\\n"),
                    c => out.push(c),
                }
            }
            out
        }
        _ => format!("hex {}", hex_text(bytes)),
    }
}

/// Bytes as hex pairs with spaces: "01 0a ff". Long ones are cut, with how many there are.
pub fn hex_text(bytes: &[u8]) -> String {
    const MOST: usize = 64;
    let shown: Vec<String> = bytes
        .iter()
        .take(MOST)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut text = shown.join(" ");
    if bytes.len() > MOST {
        text.push_str(&format!(" ... ({} bytes)", bytes.len()));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_quotes_flags_and_the_rest() {
        let mut words = Words::new(r#"  pub -q1 -r "my topic" hello  world\r\n"#);
        assert_eq!(words.peek().as_deref(), Some("pub"));
        assert_eq!(words.next().as_deref(), Some("pub"));
        assert_eq!(
            words.flags(),
            [('q', "1".to_string()), ('r', String::new())]
        );
        assert_eq!(words.next().as_deref(), Some("my topic"));
        assert_eq!(words.rest(), b"hello  world\r\n");
        assert!(words.done());
        assert_eq!(words.next(), None);
    }

    #[test]
    fn numbers_in_decimal_hex_and_binary() {
        assert_eq!(parse_number::<u16>("1234"), Some(1234));
        assert_eq!(parse_number::<u16>("0x4D2"), Some(1234));
        assert_eq!(parse_number::<u8>("0b101"), Some(5));
        assert_eq!(parse_number::<i16>("-5"), Some(-5));
        assert_eq!(parse_number::<u8>("300"), None);
        let mut words = Words::new("read 10");
        words.next();
        assert_eq!(words.number::<u16>("start"), Ok(10));
        assert!(words.number::<u16>("count").unwrap_err().contains("count"));
    }

    #[test]
    fn payloads_are_text_or_hex() {
        assert_eq!(payload_text(b"21.5"), "21.5");
        assert_eq!(payload_text(b"a\r\n"), "a\\r\\n");
        assert_eq!(payload_text(&[0, 1, 255]), "hex 00 01 ff");
        assert_eq!(payload_text(b""), "(empty)");
        assert_eq!(unescape(r"a\x41\x7"), b"aA\\x7");
    }
}
