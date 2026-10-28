//! Node 22's JSON.parse diagnostics, used only after serde refuses a body
//! or header. This scanner diagnoses syntax, never constructs a value or
//! changes the transport's verdict. Valid JSON with a Rust type mismatch
//! retains serde's diagnostic (a stated parity difference, #410).

#[derive(Clone, Copy)]
enum State {
    Value,
    ArrayFirst,
    ArrayNext,
    ObjectFirst,
    ObjectNext,
    Colon,
    End,
}

enum Failure {
    End,
    Token,
    At(&'static str),
}

struct Scanner<'a> {
    text: &'a str,
    at: usize,
}

/// None means syntactically valid JSON, or nesting past serde's own bound.
pub(super) fn diagnostic(text: &str) -> Option<String> {
    let mut scanner = Scanner { text, at: 0 };
    let mut states = vec![State::End, State::Value];
    while let Some(state) = states.pop() {
        scanner.space();
        if let Err(failure) = scanner.step(state, &mut states) {
            return Some(scanner.describe(failure));
        }
        if states.len() > 128 {
            return None;
        }
    }
    None
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.at += 1;
        }
    }

    fn step(&mut self, state: State, states: &mut Vec<State>) -> Result<(), Failure> {
        match state {
            State::Value => self.value(states),
            State::ArrayFirst if self.peek() != Some(b']') => {
                states.extend([State::ArrayNext, State::Value]);
                Ok(())
            }
            State::ArrayFirst => {
                self.at += 1;
                Ok(())
            }
            State::ArrayNext => self.separator(b']', State::ArrayNext, states),
            State::ObjectFirst => self.key(true, states),
            State::ObjectNext => self.separator(b'}', State::ObjectNext, states),
            State::Colon => {
                if self.peek() != Some(b':') {
                    return Err(Failure::At("Expected ':' after property name in JSON"));
                }
                self.at += 1;
                states.extend([State::ObjectNext, State::Value]);
                Ok(())
            }
            State::End if self.peek().is_some() => Err(Failure::At(
                "Unexpected non-whitespace character after JSON",
            )),
            State::End => Ok(()),
        }
    }

    fn key(&mut self, first: bool, states: &mut Vec<State>) -> Result<(), Failure> {
        if first && self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(());
        }
        if self.peek() != Some(b'"') {
            return Err(Failure::At(if first {
                "Expected property name or '}' in JSON"
            } else {
                "Expected double-quoted property name in JSON"
            }));
        }
        self.string()?;
        states.push(State::Colon);
        Ok(())
    }

    fn separator(&mut self, end: u8, state: State, states: &mut Vec<State>) -> Result<(), Failure> {
        if self.peek() == Some(end) {
            self.at += 1;
            return Ok(());
        }
        if self.peek() != Some(b',') {
            return Err(Failure::At(if end == b']' {
                "Expected ',' or ']' after array element in JSON"
            } else {
                "Expected ',' or '}' after property value in JSON"
            }));
        }
        self.at += 1;
        self.space();
        if end == b'}' {
            self.key(false, states)
        } else {
            states.extend([state, State::Value]);
            Ok(())
        }
    }

    fn value(&mut self, states: &mut Vec<State>) -> Result<(), Failure> {
        match self.peek() {
            Some(b'{') => {
                self.at += 1;
                states.push(State::ObjectFirst);
                Ok(())
            }
            Some(b'[') => {
                self.at += 1;
                states.push(State::ArrayFirst);
                Ok(())
            }
            Some(b'"') => self.string(),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(Failure::Token),
            None => Err(Failure::End),
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), Failure> {
        for byte in word {
            match self.peek() {
                Some(actual) if actual == *byte => self.at += 1,
                Some(_) => return Err(Failure::Token),
                None => return Err(Failure::End),
            }
        }
        Ok(())
    }

    fn digits(&mut self) -> bool {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at > start
    }

    fn number(&mut self) -> Result<(), Failure> {
        if self.peek() == Some(b'-') {
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Failure::At("No number after minus sign in JSON"));
            }
        }
        if self.peek() == Some(b'0') {
            self.at += 1;
            if matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Failure::At("Unexpected number in JSON"));
            }
        } else {
            self.digits();
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if !self.digits() {
                return Err(Failure::At("Unterminated fractional number in JSON"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !self.digits() {
                return Err(Failure::At("Exponent part is missing a number in JSON"));
            }
        }
        Ok(())
    }

    fn string(&mut self) -> Result<(), Failure> {
        self.at += 1;
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(());
                }
                0..=31 => {
                    return Err(Failure::At(
                        "Bad control character in string literal in JSON",
                    ))
                }
                b'\\' => self.escape()?,
                _ => self.at += 1,
            }
        }
        Err(Failure::At("Unterminated string in JSON"))
    }

    fn escape(&mut self) -> Result<(), Failure> {
        self.at += 1;
        match self.peek() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.at += 1,
            Some(b'u') => {
                self.at += 1;
                for _ in 0..4 {
                    if !self.peek().is_some_and(|b| b.is_ascii_hexdigit()) {
                        return Err(Failure::At("Bad Unicode escape in JSON"));
                    }
                    self.at += 1;
                }
            }
            Some(_)
                if self
                    .text
                    .get(self.at..)
                    .and_then(|text| text.chars().next())
                    .is_some_and(|c| u32::from(c) > 255) =>
            {
                return Err(Failure::Token);
            }
            Some(_) => return Err(Failure::At("Bad escaped character in JSON")),
            None => return Err(Failure::End),
        }
        Ok(())
    }

    fn describe(&self, failure: Failure) -> String {
        match failure {
            Failure::End => "Unexpected end of JSON input".into(),
            Failure::Token => self.token(),
            Failure::At(message) => {
                let prefix = self.text.get(..self.at).unwrap_or_default();
                let position = prefix.encode_utf16().count();
                let mut line = 1;
                let mut column = 1;
                let mut cr = false;
                for c in prefix.chars() {
                    if c == '\r' || (c == '\n' && !cr) {
                        line += 1;
                        column = 1;
                    } else if c != '\n' {
                        column += c.len_utf16();
                    }
                    cr = c == '\r';
                }
                format!("{message} at position {position} (line {line} column {column})")
            }
        }
    }

    fn token(&self) -> String {
        if matches!(self.peek(), Some(b'-' | b'0'..=b'9')) {
            return self.describe(Failure::At("Unexpected number in JSON"));
        }
        if self.peek() == Some(b'"') {
            return self.describe(Failure::At("Unexpected string in JSON"));
        }
        if matches!(
            self.text,
            "undefined" | "NaN" | "Infinity" | "[object Object]"
        ) {
            return format!("\"{}\" is not valid JSON", self.text);
        }
        let length = self.text.encode_utf16().count();
        let position = self
            .text
            .get(..self.at)
            .unwrap_or_default()
            .encode_utf16()
            .count();
        let token = self.utf16_slice(position, 1);
        let (start, end) = if length <= 20 {
            (0, length)
        } else {
            (position.saturating_sub(10), length.min(position + 10))
        };
        let sample = self.utf16_slice(start, end - start);
        let before = if length > 20 && position >= 10 {
            "..."
        } else {
            ""
        };
        let after = if end < length { "..." } else { "" };
        format!("Unexpected token '{token}', {before}\"{sample}\"{after} is not valid JSON")
    }

    fn utf16_slice(&self, start: usize, length: usize) -> String {
        let units: Vec<u16> = self.text.encode_utf16().skip(start).take(length).collect();
        String::from_utf16_lossy(&units)
    }
}
