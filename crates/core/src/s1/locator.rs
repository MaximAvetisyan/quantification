use crate::{Role, Span};

pub fn locate(data: &[u8]) -> Vec<Span> {
    let data = if data.len() >= 3 && data[..3] == [0xEF, 0xBB, 0xBF] {
        &data[3..]
    } else {
        data
    };
    let mut sc = Scanner { data };
    let mut out = Vec::new();
    sc.run(&mut out);
    out
}

struct Scanner<'a> {
    data: &'a [u8],
}

#[derive(Clone, Copy)]
struct Msg {
    role: u8,
    content: Option<(usize, usize)>,
}

impl Msg {
    fn new() -> Self {
        Msg {
            role: 0,
            content: None,
        }
    }
}

impl<'a> Scanner<'a> {
    fn run(&mut self, out: &mut Vec<Span>) {
        let d = self.data;
        if d.first() != Some(&b'{') {
            return;
        }
        let mut depth: usize = 1;
        let mut i = 1;
        while i < d.len() {
            match d[i] {
                b' ' | b'\t' | b'\n' | b'\r' => i += 1,
                b'"' => {
                    let (ks, ke, next) = match scan_string(d, i) {
                        Some(t) => t,
                        None => return,
                    };
                    if &d[ks..ke] == b"messages" {
                        let vi = match self.value_start(next) {
                            Some(p) => p,
                            None => return,
                        };
                        depth += 1;
                        if !self.scan_messages(vi, &mut depth, out) {
                            out.clear();
                        }
                        return;
                    }
                    let vi = match self.value_start(next) {
                        Some(p) => p,
                        None => return,
                    };
                    let (_, _, n2) = match skip_value(d, vi) {
                        Some(t) => t,
                        None => return,
                    };
                    i = n2;
                }
                b':' => i += 1,
                b',' => i += 1,
                b'}' => {
                    depth -= 1;
                    i += 1;
                    if depth == 0 {
                        while i < d.len() && matches!(d[i], b' ' | b'\t' | b'\n' | b'\r') {
                            i += 1;
                        }
                        if i != d.len() {
                            out.clear();
                        }
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    fn value_start(&self, mut i: usize) -> Option<usize> {
        while i < self.data.len() && matches!(self.data[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= self.data.len() || self.data[i] != b':' {
            return None;
        }
        i += 1;
        while i < self.data.len() && matches!(self.data[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        Some(i)
    }

    fn scan_messages(&mut self, mut i: usize, depth: &mut usize, out: &mut Vec<Span>) -> bool {
        let d = self.data;
        if i >= d.len() || d[i] != b'[' {
            return false;
        }
        i += 1;
        *depth += 1;
        if *depth > 64 {
            return false;
        }
        loop {
            while i < d.len() && matches!(d[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
                i += 1;
            }
            if i >= d.len() {
                return false;
            }
            if d[i] == b']' {
                *depth -= 1;
                return true;
            }
            if d[i] != b'{' {
                return false;
            }
            *depth += 1;
            if *depth > 64 {
                return false;
            }
            let start = i + 1;
            let mut msg = Msg::new();
            let mut j = start;
            loop {
                while j < d.len() && matches!(d[j], b' ' | b'\t' | b'\n' | b'\r' | b',') {
                    j += 1;
                }
                if j >= d.len() || d[j] == b'}' {
                    break;
                }
                if d[j] != b'"' {
                    return false;
                }
                let (ks, ke, after_key) = match scan_string(d, j) {
                    Some(t) => t,
                    None => return false,
                };
                let key = &d[ks..ke];
                j = match self.value_start(after_key) {
                    Some(p) => p,
                    None => return false,
                };
                let (vs, ve, after_val) = match scan_string(d, j) {
                    Some(t) => t,
                    None => return false,
                };
                if key == b"role" {
                    msg.role = match &d[vs..ve] {
                        b"tool" => b't',
                        b"user" => b'u',
                        _ => 0,
                    };
                } else if key == b"content" {
                    msg.content = Some((vs, ve));
                }
                j = after_val;
            }
            i = j;
            if let Some((s, e)) = msg.content.filter(|_| msg.role != 0) {
                out.push(Span {
                    start: s,
                    end: e,
                    role: if msg.role == b't' {
                        Role::Tool
                    } else {
                        Role::User
                    },
                });
            }
            if i >= d.len() || d[i] != b'}' {
                return false;
            }
            i += 1;
            *depth -= 1;
        }
    }
}

fn scan_string(d: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    if d[i] != b'"' {
        return None;
    }
    let mut j = i + 1;
    while j < d.len() {
        match d[j] {
            b'\\' => {
                if j + 1 >= d.len() {
                    return None;
                }
                j += 2;
            }
            b'"' => return Some((i + 1, j, j + 1)),
            0..=0x1F => return None,
            _ => j += 1,
        }
    }
    None
}

fn skip_value(d: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    scan_string(d, i)
}
