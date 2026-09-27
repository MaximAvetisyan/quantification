use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use quantification_core::api::{self, Compressor as Api, Request};
use quantification_core::config::{
    MAX_LINE_BYTES, MAX_RECORD_BYTES, MarkerStyle, RawOptions, ResolvedOptions, ScopePolicy,
    resolve,
};
use quantification_core::fingerprint::marker_checksum;
use quantification_core::ledger::{Commit, CommitKind, marker_len, profitable, removal_range};
use quantification_core::locator;
use quantification_core::mask;
use quantification_core::pipeline::{Clock, Compressor, Stats};
use quantification_core::render;
use quantification_core::sniff::{self, Schema};
use quantification_core::splice::spliced_len;
use quantification_core::stage1::{self, Unit};
use quantification_core::wsnorm;

const NEWLINES: [&str; 3] = [r"\n", r"\u000A", r"\u000a"];
const PADS: [&str; 4] = ["", "  ", r"\t", r" \t "];
const SHAPES: usize = 14;
const SEED: u64 = 0x4d31_5eed_0001;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn between(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high - low + 1)
    }

    fn flag(&mut self) -> bool {
        self.below(2) == 0
    }
}

fn stamp(rng: &mut Rng, salt: usize) -> String {
    format!(
        "2026-08-2{}T{:02}:{:02}:{:02}Z",
        3 + rng.below(3),
        salt % 24,
        rng.below(60),
        rng.below(60)
    )
}

fn ipv4(rng: &mut Rng) -> String {
    format!(
        "10.{}.{}.{}",
        rng.below(4),
        rng.below(256),
        rng.between(1, 254)
    )
}

fn uuid(rng: &mut Rng) -> String {
    format!(
        "{:08x}-1111-2222-3333-{:012x}",
        rng.next() as u32,
        rng.below(1 << 40)
    )
}

fn log_line(rng: &mut Rng, kind: usize, entry: usize) -> String {
    let tail = match kind % 4 {
        0 => format!("GET /v1/users?id={entry} status=200"),
        1 => format!("<- 200 bytes {} upstream=primary", 4000 + entry),
        2 => format!("pool conns {entry} idle {} queue=7", rng.below(8)),
        _ => format!("worker node {} parked lease {}ms", ipv4(rng), 5 * entry),
    };
    format!(
        "{} INFO hc {} {} id={} took {}ms",
        stamp(rng, entry),
        ipv4(rng),
        tail,
        uuid(rng),
        3 * entry
    )
}

fn log_burst(rng: &mut Rng, nl: &str) -> String {
    let mut lines = Vec::new();
    for group in 0..1 + rng.below(3) {
        lines.push(log_line(rng, 3, group * 7));
        let pattern: Vec<usize> = (0..1 + rng.below(3)).map(|_| rng.below(4)).collect();
        for entry in 0..2 + rng.below(3) {
            for kind in &pattern {
                lines.push(log_line(rng, *kind, group * 7 + entry));
            }
        }
        if rng.flag() {
            let previous = lines.clone();
            for (offset, line) in previous.into_iter().enumerate() {
                if offset % 3 == 0 {
                    lines.push(line);
                } else {
                    lines.push(log_line(rng, offset, group + offset));
                }
            }
        }
    }
    lines.join(nl)
}

fn exact_run(rng: &mut Rng, nl: &str) -> String {
    let body = format!(
        "{} ERROR timeout while connecting to the primary database shard {}",
        stamp(rng, 1),
        "x".repeat(20 + rng.below(60))
    );
    let mut lines = vec![body; 3 + rng.below(20)];
    if rng.flag() {
        lines.insert(
            1 + rng.below(lines.len() - 1),
            format!("{} DEBUG unique tail {:016x}", stamp(rng, 2), rng.next()),
        );
    }
    lines.join(nl)
}

fn padded_run(rng: &mut Rng, nl: &str) -> String {
    let body = format!(
        "{} WARN retrying the secondary replica after a slow handshake id={}",
        stamp(rng, 3),
        uuid(rng)
    );
    let lines: Vec<String> = (0..3 + rng.below(10))
        .map(|_| {
            let pad = PADS[rng.below(PADS.len())];
            format!("{pad}{body}{pad}")
        })
        .collect();
    lines.join(nl)
}

fn near_block(rng: &mut Rng, nl: &str) -> String {
    let period = 2 + rng.below(4);
    let copies = 2 + rng.below(4);
    let mut lines = Vec::new();
    for copy in 0..copies {
        for step in 0..period {
            lines.push(format!(
                "{} trace step {step} of {period} at {} shard={} took {}ms",
                stamp(rng, copy),
                ipv4(rng),
                rng.below(4),
                7 * copy + step
            ));
        }
    }
    if rng.flag() {
        for step in 0..period {
            lines.push(format!(
                "{} trace tail {step} unique {:016x}",
                stamp(rng, step),
                rng.next()
            ));
        }
    }
    lines.join(nl)
}

fn record_line(entry: usize, len: usize) -> String {
    let head = format!("{{\\\"id\\\":{entry},\\\"name\\\":\\\"worker-{entry}\\\",\\\"pad\\\":\\\"");
    let tail = "\\\",\\\"state\\\":\\\"ok\\\"}";
    let padding = len - head.len() - tail.len();
    let mut out = head;
    out.extend(std::iter::repeat_n('p', padding));
    out.push_str(tail);
    out
}

fn record_dump(record_len: usize, records: usize, copies: usize) -> String {
    let mut out = String::from("[");
    let mut at = 0;
    for _ in 0..copies {
        for _ in 0..records {
            if at > 0 {
                out.push(',');
            }
            out.push_str(&record_line(at, record_len));
            at += 1;
        }
    }
    out.push(']');
    out
}

fn tool_dump(rng: &mut Rng) -> String {
    if rng.below(6) == 0 {
        let len = 120 + rng.below(400);
        let records = 1 + MAX_LINE_BYTES / len + rng.below(8);
        return record_dump(len, records, 1 + rng.below(3));
    }
    record_dump(64 + rng.below(60), 2 + rng.below(6), 1 + rng.below(4))
}

fn record_cap(rng: &mut Rng) -> String {
    let len = [MAX_RECORD_BYTES - 1, MAX_RECORD_BYTES, MAX_RECORD_BYTES + 1][rng.below(3)];
    record_dump(len, 3 + rng.below(3), 1 + rng.below(2))
}

const PRIOR_MARKERS: [&str; 6] = [
    "\u{27ea}\u{d7}200 identical \u{b7}c5f3\u{27eb}",
    "[... x50 rows, template 0abc ...]",
    "\u{27ea}block \u{d7}12 \u{b7}d4e5\u{27eb}",
    "[... x200 identical c5f3 ..",
    "\u{27ea}\u{d7}200 identical \u{b7}\u{27eb}",
    "[... x200 rows, templatee c5f3 ...]",
];

fn marker_payload(rng: &mut Rng, nl: &str) -> String {
    let marker = PRIOR_MARKERS[rng.below(PRIOR_MARKERS.len())];
    let body = format!(
        "{} INFO hc {} prior marker line id={}",
        stamp(rng, 4),
        ipv4(rng),
        uuid(rng)
    );
    let mut lines = vec![format!("{body}{marker}"); 2 + rng.below(6)];
    if rng.flag() {
        let other = PRIOR_MARKERS[(rng.below(PRIOR_MARKERS.len()) + 4) % PRIOR_MARKERS.len()];
        lines.push(format!("{body}{other}"));
    }
    for entry in 0..1 + rng.below(4) {
        let kind = rng.below(4);
        lines.push(log_line(rng, kind, 40 + entry));
    }
    lines.join(nl)
}

fn near_miss(rng: &mut Rng, nl: &str) -> String {
    match rng.below(6) {
        0 => {
            let body = format!("{} INFO near miss pair unchanged", stamp(rng, 5));
            let different = format!("{body} but different");
            [body.clone(), body, different].join(nl)
        }
        1 => {
            let body = format!("{} INFO a group of exactly two copies", stamp(rng, 6));
            let second = body.clone();
            [body, second].join(nl)
        }
        2 => {
            let mut lines = Vec::new();
            for step in 0..3 + rng.below(3) {
                lines.push(format!(
                    "{} INFO period three at {} step {step}",
                    stamp(rng, step),
                    ipv4(rng)
                ));
            }
            lines.push(format!(
                "{} INFO period tail {:016x}",
                stamp(rng, 9),
                rng.next()
            ));
            lines.join(nl)
        }
        3 => {
            let len = if rng.flag() { 7 } else { 8 };
            vec![std::iter::repeat_n('a', len).collect::<String>(); 4].join(nl)
        }
        4 => record_dump(64 + rng.below(8), 2, 1),
        _ => {
            let body = format!("{} INFO split by a neighbour", stamp(rng, 7));
            let unique = format!("{} INFO unique {:016x}", stamp(rng, 8), rng.next());
            let again = body.clone();
            [body.clone(), unique, again, body].join(nl)
        }
    }
}

fn ws_paired_block(rng: &mut Rng, nl: &str) -> String {
    let body = format!(
        "{} INFO hc {} a paired ws line id={} took {}ms",
        stamp(rng, 9),
        ipv4(rng),
        uuid(rng),
        5 + rng.below(9)
    );
    let other = format!(
        "{} ERROR the third line of every copy differs id={}",
        stamp(rng, 10),
        uuid(rng)
    );
    let mut lines = Vec::new();
    for _ in 0..2 + rng.below(3) {
        let left = PADS[rng.below(2)];
        let right = PADS[2 + rng.below(2)];
        lines.push(format!("{left}{body}{right}"));
        lines.push(format!("{right}{body}{left}"));
        lines.push(other.clone());
    }
    lines.join(nl)
}

fn verbatim_block(rng: &mut Rng, nl: &str) -> String {
    let period = 2 + rng.below(4);
    let block: Vec<String> = (0..period)
        .map(|step| log_line(rng, step % 4, 50 + step))
        .collect();
    let mut lines = vec![log_line(rng, 3, 60)];
    for _ in 0..2 + rng.below(4) {
        lines.extend(block.iter().cloned());
    }
    if rng.flag() {
        lines.push(log_line(rng, 2, 70));
    }
    lines.join(nl)
}

fn mixed_newlines(rng: &mut Rng) -> String {
    let lines: Vec<String> = (0..3 + rng.below(8))
        .map(|entry| log_line(rng, 0, entry))
        .collect();
    let mut out = lines[0].clone();
    for line in &lines[1..] {
        out.push_str(NEWLINES[rng.below(NEWLINES.len())]);
        out.push_str(line);
    }
    out
}

fn unicode_span(rng: &mut Rng, nl: &str) -> String {
    let notes = [
        "caf\u{e9} r\u{e9}sum\u{e9}",
        "\u{4e2d}\u{6587} \u{65e5}\u{5fd7}",
        "\u{2192} \u{2713} \u{2717}",
    ];
    let lines: Vec<String> = (0..3 + rng.below(8))
        .map(|entry| {
            format!(
                "{} INFO caf\u{e9} {} id={} took {}ms",
                stamp(rng, entry),
                notes[rng.below(notes.len())],
                uuid(rng),
                entry
            )
        })
        .collect();
    lines.join(nl)
}

fn unique_span(rng: &mut Rng, nl: &str) -> String {
    let lines: Vec<String> = (0..3 + rng.below(10))
        .map(|entry| {
            format!(
                "{} NOTE unique {:016x} nothing repeats here",
                stamp(rng, entry),
                rng.next()
            )
        })
        .collect();
    lines.join(nl)
}

fn tiny_span(rng: &mut Rng, nl: &str) -> String {
    match rng.below(5) {
        0 => String::new(),
        1 => String::from("a"),
        2 => format!("a{nl}b"),
        3 => format!("{}{nl}{}", log_line(rng, 1, 1), log_line(rng, 2, 2)),
        _ => format!("{nl}{nl}{nl}"),
    }
}

fn span_content(rng: &mut Rng, shape: usize) -> String {
    let nl = NEWLINES[rng.below(NEWLINES.len())];
    match shape {
        0 => log_burst(rng, nl),
        1 => exact_run(rng, nl),
        2 => padded_run(rng, nl),
        3 => near_block(rng, nl),
        4 => tool_dump(rng),
        5 => marker_payload(rng, nl),
        6 => near_miss(rng, nl),
        7 => mixed_newlines(rng),
        8 => unicode_span(rng, nl),
        9 => unique_span(rng, nl),
        10 => record_cap(rng),
        11 => tiny_span(rng, nl),
        12 => ws_paired_block(rng, nl),
        _ => verbatim_block(rng, nl),
    }
}

const SLOTS: [[&str; 4]; 3] = [
    ["user", "tool", "assistant", "textpart"],
    ["input", "funcout", "user", "user"],
    ["user", "tool_result", "textpart", "user"],
];

fn chat_message(role: &str, content: &str) -> String {
    format!(r#"{{"role":"{role}","content":"{content}"}}"#)
}

fn text_part(content: &str) -> String {
    format!(r#"{{"role":"user","content":[{{"type":"text","text":"{content}"}}]}}"#)
}

fn chat_item(slot: &str, content: &str) -> String {
    match slot {
        "tool" => chat_message("tool", content),
        "assistant" => chat_message("assistant", content),
        "textpart" => text_part(content),
        _ => chat_message("user", content),
    }
}

fn chat_payload(slots: &[(&str, String)], pretty: bool) -> String {
    let items: Vec<String> = slots
        .iter()
        .map(|(slot, content)| chat_item(slot, content))
        .collect();
    if pretty {
        format!(
            "{{\n  \"model\": \"quantification-test\",\n  \"messages\": [\n    {}\n  ]\n}}",
            items.join(",\n    ")
        )
    } else {
        format!(
            r#"{{"model":"quantification-test","messages":[{}]}}"#,
            items.join(",")
        )
    }
}

fn responses_payload(slots: &[(&str, String)], pretty: bool) -> String {
    if slots.iter().all(|(slot, _)| *slot == "input") {
        let content = &slots[0].1;
        return if pretty {
            format!("{{\n  \"model\": \"quantification-test\",\n  \"input\": \"{content}\"\n}}")
        } else {
            format!(r#"{{"model":"quantification-test","input":"{content}"}}"#)
        };
    }
    let items: Vec<String> = slots
        .iter()
        .map(|(slot, content)| {
            if *slot == "funcout" {
                format!(r#"{{"type":"function_call_output","output":"{content}"}}"#)
            } else {
                chat_message("user", content)
            }
        })
        .collect();
    if pretty {
        format!(
            "{{\n  \"model\": \"quantification-test\",\n  \"input\": [\n    {}\n  ]\n}}",
            items.join(",\n    ")
        )
    } else {
        format!(
            r#"{{"model":"quantification-test","input":[{}]}}"#,
            items.join(",")
        )
    }
}

fn messages_payload(slots: &[(&str, String)], pretty: bool) -> String {
    let items: Vec<String> = slots
        .iter()
        .map(|(slot, content)| match *slot {
            "tool_result" => format!(
                r#"{{"role":"user","content":[{{"type":"tool_result","content":"{content}"}}]}}"#
            ),
            "textpart" => text_part(content),
            _ => chat_message("user", content),
        })
        .collect();
    if pretty {
        format!(
            "{{\n  \"model\": \"quantification-test\",\n  \"max_tokens\": 16,\n  \"messages\": [\n    {}\n  ]\n}}",
            items.join(",\n    ")
        )
    } else {
        format!(
            r#"{{"model":"quantification-test","max_tokens":16,"messages":[{}]}}"#,
            items.join(",")
        )
    }
}

fn option_sets() -> Vec<ResolvedOptions> {
    let raws = [
        RawOptions::default(),
        RawOptions {
            scope_policy: Some(ScopePolicy::UserAndTools),
            ..RawOptions::default()
        },
        RawOptions {
            marker_style: Some(MarkerStyle::Ascii),
            ..RawOptions::default()
        },
        RawOptions {
            marker_style: Some(MarkerStyle::Unicode),
            ..RawOptions::default()
        },
        RawOptions {
            min_group_size: Some(2),
            ..RawOptions::default()
        },
        RawOptions {
            min_group_size: Some(7),
            ..RawOptions::default()
        },
        RawOptions {
            normalize_ws: Some(false),
            ..RawOptions::default()
        },
        RawOptions {
            template_dedup: Some(false),
            ..RawOptions::default()
        },
        RawOptions {
            scope_policy: Some(ScopePolicy::UserAndTools),
            marker_style: Some(MarkerStyle::Ascii),
            min_group_size: Some(4),
            ..RawOptions::default()
        },
    ];
    raws.iter()
        .map(|raw| resolve(raw).expect("options resolve"))
        .collect()
}

#[derive(Clone)]
struct Case {
    name: String,
    payload: Vec<u8>,
    options: ResolvedOptions,
}

fn corpus(count: usize, seed: u64) -> Vec<Case> {
    let mut rng = Rng(seed);
    let options = option_sets();
    (0..count)
        .map(|at| {
            let schema = rng.below(4);
            let pretty = rng.flag();
            let bom = rng.below(8) == 0;
            let spans = 1 + rng.below(3);
            let mut slots: Vec<(&str, String)> = Vec::new();
            for _ in 0..spans {
                let shape = rng.below(SHAPES);
                let content = span_content(&mut rng, shape);
                let slot = if schema == 3 {
                    ""
                } else {
                    SLOTS[schema][rng.below(SLOTS[schema].len())]
                };
                slots.push((slot, content));
            }
            let body = if schema == 3 {
                slots[0].1.clone()
            } else {
                match schema {
                    0 => chat_payload(&slots, pretty),
                    1 => responses_payload(&slots, pretty),
                    _ => messages_payload(&slots, pretty),
                }
            };
            let mut payload = Vec::new();
            if bom {
                payload.extend_from_slice(&[0xef, 0xbb, 0xbf]);
            }
            payload.extend_from_slice(body.as_bytes());
            Case {
                name: format!("case {at} schema {schema} spans {spans}"),
                payload,
                options: options[rng.below(options.len())],
            }
        })
        .collect()
}

struct Output {
    payload: Vec<u8>,
    commits: Vec<Commit>,
    stats: Stats,
}

fn compress(case: &Case) -> Output {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let stats = compressor.compress(&case.payload, &case.options, &mut out);
    Output {
        payload: out,
        commits: compressor.commits().to_vec(),
        stats,
    }
}

fn again(case: &Case, payload: Vec<u8>, pass: usize) -> Case {
    Case {
        name: format!("{} pass {pass}", case.name),
        payload,
        options: case.options,
    }
}

fn request(case: &Case) -> Request {
    Request::default().with_options(RawOptions {
        scope_policy: Some(case.options.scope_policy),
        min_group_size: Some(case.options.min_group_size),
        normalize_ws: Some(case.options.normalize_ws),
        template_dedup: Some(case.options.template_dedup),
        marker_style: Some(case.options.marker_style),
        reversible: Some(case.options.reversible),
    })
}

fn show(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).replace('\n', " ")
}

fn marker_len_of(commit: &Commit) -> usize {
    marker_len(commit.style, commit.kind, commit.count)
}

// ---------------------------------------------------------------- R3 oracle

fn json_ok(bytes: &[u8]) -> bool {
    let data = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let mut json = Json { bytes: data, at: 0 };
    json.value(0) && {
        json.ws();
        json.at == data.len()
    }
}

struct Json<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Json<'_> {
    fn ws(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn eat(&mut self, want: &[u8]) -> bool {
        if self.bytes[self.at..].starts_with(want) {
            self.at += want.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> bool {
        if depth > 64 {
            return false;
        }
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string(),
            Some(b't') => self.eat(b"true"),
            Some(b'f') => self.eat(b"false"),
            Some(b'n') => self.eat(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => false,
        }
    }

    fn object(&mut self, depth: usize) -> bool {
        self.at += 1;
        self.ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return true;
        }
        loop {
            self.ws();
            if !self.string() {
                return false;
            }
            self.ws();
            if self.peek() != Some(b':') {
                return false;
            }
            self.at += 1;
            if !self.value(depth + 1) {
                return false;
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }

    fn array(&mut self, depth: usize) -> bool {
        self.at += 1;
        self.ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            return true;
        }
        loop {
            if !self.value(depth + 1) {
                return false;
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }

    fn string(&mut self) -> bool {
        if self.peek() != Some(b'"') {
            return false;
        }
        self.at += 1;
        loop {
            match self.peek() {
                None | Some(0..=0x1f) => return false,
                Some(b'"') => {
                    self.at += 1;
                    return true;
                }
                Some(b'\\') => {
                    self.at += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.at += 1
                        }
                        Some(b'u') => {
                            self.at += 1;
                            for _ in 0..4 {
                                if !self.peek().is_some_and(|byte| byte.is_ascii_hexdigit()) {
                                    return false;
                                }
                                self.at += 1;
                            }
                        }
                        _ => return false,
                    }
                }
                _ => self.at += 1,
            }
        }
    }

    fn number(&mut self) -> bool {
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.at += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return false,
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if !self.digits() {
                return false;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !self.digits() {
                return false;
            }
        }
        self.ws();
        matches!(self.peek(), None | Some(b',' | b'}' | b']'))
    }

    fn digits(&mut self) -> bool {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at > start
    }
}

#[test]
fn the_test_local_json_oracle_has_teeth() {
    for good in [
        &b"{}"[..],
        b"[]",
        b"null",
        b"true",
        b"-1.5e10",
        b"\"a\\u0041b\"",
        br#"{"a":[1,{"b":null}],"c":"x"}"#,
        "\"\u{27ea}\u{d7}2 identical \u{b7}c5f3\u{27eb}\"".as_bytes(),
        &[0xef, 0xbb, 0xbf, b'{', b'}'],
    ] {
        assert!(json_ok(good), "the oracle rejected {:?}", show(good));
    }
    for bad in [
        &b""[..],
        b"{",
        b"}",
        b"[1,]",
        br#"{"a":}"#,
        b"{a:1}",
        br#"{"a":1,}"#,
        br#"{"a":01}"#,
        br#"{"a":+1}"#,
        br#"{"a":.5}"#,
        br#"{"a":1.}"#,
        br#"{"a":1e}"#,
        br#"{"a":1e+}"#,
        br#"{"a":"\q"}"#,
        br#"{"a":"\u00"}"#,
        b"{\"a\":\"unterminated}",
        b"{\"a\":\"raw\ncontrol\"}",
        b"{\"a\":1} trailing",
        b"[1 2]",
        br#"{"a":NaN}"#,
        b"tru",
        b"\"a\" \"b\"",
    ] {
        assert!(!json_ok(bad), "the oracle accepted {:?}", show(bad));
    }
    let deep: Vec<u8> = std::iter::repeat_n(b'[', 70)
        .chain(std::iter::repeat_n(b']', 70))
        .collect();
    assert!(!json_ok(&deep), "the oracle has no depth cap");
    let shallow: Vec<u8> = std::iter::repeat_n(b'[', 60)
        .chain(std::iter::repeat_n(b']', 60))
        .collect();
    assert!(json_ok(&shallow));
}

// ---------------------------------------------------------------- R3 parse validity

#[test]
fn every_generated_output_parses_as_json_or_stays_text() {
    let cases = corpus(512, SEED);
    let (mut json, mut text, mut compressed, mut text_compressed, mut bytes) = (0, 0, 0, 0, 0usize);
    for case in &cases {
        let run = compress(case);
        bytes += run.payload.len();
        match sniff::sniff(&case.payload) {
            Some(Schema::Text) | None => {
                text += 1;
                assert!(
                    std::str::from_utf8(&run.payload).is_ok(),
                    "{}: a text payload stopped being text: {:?}",
                    case.name,
                    show(&run.payload)
                );
                assert_eq!(
                    sniff::sniff(&run.payload),
                    sniff::sniff(&case.payload),
                    "{}: a text payload changed schema",
                    case.name
                );
                if !run.commits.is_empty() {
                    text_compressed += 1;
                }
            }
            Some(schema) => {
                json += 1;
                assert!(
                    json_ok(&case.payload),
                    "{}: the generator emitted invalid json",
                    case.name
                );
                assert!(
                    json_ok(&run.payload),
                    "{} ({}) produced unparsable json: {:?}",
                    case.name,
                    schema.as_str(),
                    show(&run.payload)
                );
            }
        }
        if !run.commits.is_empty() {
            compressed += 1;
        }
    }
    assert_eq!(cases.len(), 512);
    assert!(json * 2 >= cases.len(), "only {json} json payloads");
    assert!(text >= 64, "only {text} text payloads");
    assert!(
        text_compressed >= 32,
        "only {text_compressed} text payloads compressed"
    );
    assert!(
        compressed * 2 >= cases.len(),
        "only {compressed} of {} payloads committed: the oracle is barely exercised",
        cases.len()
    );
    assert!(bytes > 500_000, "the corpus is only {bytes} bytes");
}

// ---------------------------------------------------------------- output = input except the splices

#[test]
fn the_output_is_the_input_outside_the_committed_ranges() {
    let cases = corpus(512, SEED ^ 0x11);
    let (mut commits_seen, mut copied, mut regions) = (0usize, 0usize, 0usize);
    for case in &cases {
        let run = compress(case);
        let input = &case.payload;
        let mut cursor = 0usize;
        let mut read = 0usize;
        let mut spliced: Vec<(&Commit, Range<usize>)> = Vec::new();
        for commit in &run.commits {
            assert!(
                read <= commit.removed.start && commit.removed.end <= input.len(),
                "{}: commit {:?} is out of order or out of bounds",
                case.name,
                commit.removed
            );
            let gap = commit.removed.start - read;
            assert_eq!(
                &run.payload[cursor..cursor + gap],
                &input[read..commit.removed.start],
                "{}: bytes outside the committed ranges changed",
                case.name
            );
            cursor += gap;
            copied += gap;
            let anchor = &input[commit.anchor.clone()];
            assert_eq!(
                &run.payload[cursor..cursor + anchor.len()],
                anchor,
                "{}: the anchor is not the input's own bytes",
                case.name
            );
            cursor += anchor.len();
            let len = marker_len_of(commit);
            assert_eq!(
                &run.payload[cursor..cursor + len],
                &render::render(commit.style, commit.kind, commit.count, anchor)[..],
                "{}: the spliced marker is not the rendered marker",
                case.name
            );
            cursor += len;
            let start = cursor - anchor.len() - len;
            spliced.push((commit, start..cursor));
            read = commit.removed.end;
            commits_seen += 1;
        }
        let tail = input.len() - read;
        assert_eq!(
            &run.payload[cursor..cursor + tail],
            &input[read..],
            "{}: the tail after the last commit changed",
            case.name
        );
        copied += tail;
        cursor += tail;
        assert_eq!(cursor, run.payload.len(), "{}", case.name);
        assert_eq!(
            run.payload.len(),
            spliced_len(input.len(), &run.commits),
            "{}: the output length is not the spliced length",
            case.name
        );
        assert_eq!(
            run.stats.bytes_out as usize,
            run.payload.len(),
            "{}",
            case.name
        );
        assert_eq!(
            run.stats.groups_collapsed as usize,
            run.commits.len(),
            "{}",
            case.name
        );
        let mut rebuilt = run.payload.clone();
        for (commit, at) in spliced.iter().rev() {
            let input_bytes = input[commit.removed.clone()].to_vec();
            rebuilt.splice(at.clone(), input_bytes);
            regions += 1;
        }
        assert_eq!(
            rebuilt, *input,
            "{}: the splices are not reversible",
            case.name
        );
    }
    assert!(
        commits_seen >= 200,
        "only {commits_seen} commits over 512 payloads: the property is vacuous"
    );
    assert!(copied > 500_000, "only {copied} input bytes were compared");
    assert_eq!(regions, commits_seen);
}

// ---------------------------------------------------------------- the marker grammar

const GRAMMAR: [(CommitKind, &str, &str, &str, &str); 5] = [
    (
        CommitKind::ExactRun,
        "x",
        " identical",
        "\u{d7}",
        " identical",
    ),
    (
        CommitKind::WsRun,
        "x",
        " rows, ws-equal",
        "\u{d7}",
        " rows, ws-equal",
    ),
    (CommitKind::Block, "block x", "", "block \u{d7}", ""),
    (
        CommitKind::TemplateGroup,
        "x",
        " rows, template",
        "\u{d7}",
        " rows, template",
    ),
    (
        CommitKind::TemplatedBlock,
        "templated block x",
        "",
        "templated block \u{d7}",
        "",
    ),
];

fn parse_marker(marker: &str) -> Option<(MarkerStyle, CommitKind, u64, String)> {
    let (open, sep, close, style) = if marker.starts_with("[... ") {
        ("[... ", " ", " ...]", MarkerStyle::Ascii)
    } else {
        ("\u{27ea}", " \u{b7}", "\u{27eb}", MarkerStyle::Unicode)
    };
    let rest = marker.strip_prefix(open)?;
    let mut found = Vec::new();
    for (kind, ascii_head, ascii_tail, uni_head, uni_tail) in GRAMMAR {
        let (head, tail) = if style == MarkerStyle::Ascii {
            (ascii_head, ascii_tail)
        } else {
            (uni_head, uni_tail)
        };
        let Some(after_head) = rest.strip_prefix(head) else {
            continue;
        };
        let digits: String = after_head
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if digits.is_empty() || digits.starts_with('0') {
            continue;
        }
        let Some(after_tail) = after_head[digits.len()..].strip_prefix(tail) else {
            continue;
        };
        let Some(after_sep) = after_tail.strip_prefix(sep) else {
            continue;
        };
        if after_sep.len() <= close.len() || !after_sep.ends_with(close) {
            continue;
        }
        found.push((
            style,
            kind,
            digits.parse().expect("a count"),
            after_sep[..after_sep.len() - close.len()].to_string(),
        ));
    }
    if found.len() == 1 { found.pop() } else { None }
}

#[test]
fn every_emitted_marker_matches_the_grammar_and_is_escape_safe() {
    let cases = corpus(512, SEED ^ 0x22);
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    let mut styles: BTreeMap<&str, usize> = BTreeMap::new();
    let mut markers = 0usize;
    for case in &cases {
        let run = compress(case);
        let input = &case.payload;
        let mut read = 0usize;
        let mut cursor = 0usize;
        for commit in &run.commits {
            cursor += commit.removed.start - read;
            let anchor = &input[commit.anchor.clone()];
            cursor += anchor.len();
            let len = marker_len_of(commit);
            let bytes = &run.payload[cursor..cursor + len];
            cursor += len;
            read = commit.removed.end;
            markers += 1;

            assert!(
                !bytes.iter().any(|byte| *byte < 0x20 || *byte == 0x7f),
                "{}: a control byte reached a marker: {:?}",
                case.name,
                show(bytes)
            );
            assert!(
                !bytes.iter().any(|byte| matches!(byte, b'"' | b'\\')),
                "{}: a quote or a backslash reached a marker: {:?}",
                case.name,
                show(bytes)
            );
            let text = std::str::from_utf8(bytes).expect("a marker is valid utf-8");
            let (style, kind, count, checksum) = parse_marker(text)
                .unwrap_or_else(|| panic!("{}: {text:?} is not a section 4.5 marker", case.name));
            assert_eq!(style, commit.style, "{}", case.name);
            assert_eq!(kind, commit.kind, "{}", case.name);
            assert_eq!(count, commit.count, "{}", case.name);
            assert!(count > 0, "{}", case.name);
            assert_eq!(checksum.len(), 4, "{}", case.name);
            assert!(
                checksum
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{}: {checksum} is not four lowercase hex digits",
                case.name
            );
            assert_eq!(
                u16::from_str_radix(&checksum, 16).expect("hex"),
                marker_checksum(anchor),
                "{}: the checksum is not the low 16 bits of the anchor hash",
                case.name
            );
            let quoted = format!("\"{text}\"");
            assert!(
                json_ok(quoted.as_bytes()),
                "{}: the marker is not valid inside a json string",
                case.name
            );
            *kinds.entry(kind_name(kind)).or_default() += 1;
            *styles
                .entry(if style == MarkerStyle::Ascii {
                    "ascii"
                } else {
                    "unicode"
                })
                .or_default() += 1;
        }
    }
    assert!(markers >= 200, "only {markers} markers");
    assert_eq!(
        kinds.len(),
        5,
        "not every commit kind was emitted: {kinds:?}"
    );
    for (kind, count) in &kinds {
        assert!(*count > 5, "{kind} was emitted only {count} times");
    }
    assert_eq!(
        styles.len(),
        2,
        "not every marker style was emitted: {styles:?}"
    );
    for (style, count) in &styles {
        assert!(*count > 20, "{style} markers are barely exercised: {count}");
    }
}

fn output_offsets(commits: &[Commit]) -> Vec<usize> {
    let mut at = 0usize;
    let mut read = 0usize;
    commits
        .iter()
        .map(|commit| {
            at += commit.removed.start - read;
            read = commit.removed.end;
            let start = at;
            at += commit.anchor.len() + marker_len_of(commit);
            start
        })
        .collect()
}

fn hides_a_period_one(case: &Case, once: &Output, second: &Output, commit: &Commit) -> bool {
    if commit.kind != CommitKind::TemplatedBlock || commit.last != commit.first + 1 {
        return false;
    }
    let hosted = once
        .commits
        .iter()
        .zip(output_offsets(&once.commits))
        .any(|(host, start)| {
            let end = start + host.anchor.len() + marker_len_of(host);
            start <= commit.removed.start && commit.removed.end <= end
        });
    if !hosted {
        return false;
    }
    let Some(span) = claims_of(case, second)
        .into_iter()
        .find(|span| span.start <= commit.removed.start && commit.removed.end <= span.end)
    else {
        return false;
    };
    let members = &span.units[commit.first..=commit.last];
    members.len() == 2
        && wsnorm::normalize(
            &case.payload[span.start + members[0].range.start..][..members[0].range.len()],
        ) == wsnorm::normalize(
            &case.payload[span.start + members[1].range.start..][..members[1].range.len()],
        )
}

#[test]
fn every_generated_divergence_is_a_block_anchor_hiding_a_period_one_repetition() {
    let cases = corpus(2048, SEED ^ 0x33);
    let (mut compressed, mut diverged) = (0usize, 0usize);
    for case in &cases {
        let once = compress(case);
        if once.commits.is_empty() {
            assert_eq!(once.payload, case.payload, "{}", case.name);
            continue;
        }
        compressed += 1;
        let second_case = again(case, once.payload.clone(), 2);
        let second = compress(&second_case);
        if second.payload == once.payload {
            continue;
        }
        diverged += 1;
        for commit in &second.commits {
            assert!(
                hides_a_period_one(&second_case, &once, &second, commit),
                "{}: an unclassified divergence, the second pass committed {:?} {:?} over {:?}",
                case.name,
                commit.kind,
                commit.removed,
                show(&once.payload[commit.removed.clone()]),
            );
        }
        let third = compress(&again(case, second.payload.clone(), 3));
        assert_eq!(
            third.payload, second.payload,
            "{}: the third pass is not the fixed point either",
            case.name
        );
    }
    assert_eq!(cases.len(), 2048);
    assert!(
        compressed * 5 >= cases.len() * 3,
        "only {compressed} of {} payloads compress",
        cases.len()
    );
    assert_eq!(
        diverged, DIVERGENT_PAYLOADS,
        "the measured divergence count moved: every one of them must be a block anchor hiding a \
         period-one repetition, and the pins below name the mechanism"
    );
}

const DIVERGENT_PAYLOADS: usize = 0;

#[test]
fn a_block_anchor_that_hides_a_period_one_repetition_is_refused() {
    let body = "2026-08-25T10:00:01Z INFO hc 10.0.0.1 took 5ms ok padding";
    let other = "2026-08-25T10:00:01Z ERROR a completely different line of its own";
    let lines = [
        format!("  {body}"),
        format!("{body}  "),
        other.to_string(),
        format!("  {body}"),
        format!("{body}  "),
        other.to_string(),
    ];
    let payload = lines.join(r"\n").into_bytes();
    let case = Case {
        name: String::from("a ws-equal pair inside a repeated three line block"),
        payload,
        options: resolve(&RawOptions::default()).expect("resolve"),
    };
    assert_eq!(
        wsnorm::normalize(&case.payload[lines[0].len() + 2..][..lines[0].len()]),
        wsnorm::normalize(&case.payload[..lines[0].len()]),
        "the two padded lines are ws-equal but raw-different"
    );
    let once = compress(&case);
    assert!(
        !once
            .commits
            .iter()
            .any(|commit| commit.kind == CommitKind::Block),
        "stage five must refuse a block whose anchor hides a period-one repetition: {:?}",
        once.commits
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last, commit.count))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        once.commits
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [
            (CommitKind::TemplatedBlock, 0, 1, 1),
            (CommitKind::TemplatedBlock, 3, 4, 1)
        ],
        "stage seven folds the two ws-equal lines the anchor would have hidden"
    );
    let second = compress(&again(&case, once.payload.clone(), 2));
    assert_eq!(
        second.payload, once.payload,
        "the first pass is a fixed point, which is what DESIGN 4.4 claims"
    );
    assert_eq!(second.commits.len(), 0);
    let third = compress(&again(&case, second.payload.clone(), 3));
    assert_eq!(third.payload, once.payload);
    assert_eq!(third.commits.len(), 0);
}

#[test]
fn a_block_anchor_that_hides_a_mask_equal_but_ws_distinct_pair_is_refused() {
    let first = "2026-08-25T10:00:01Z INFO hc 10.0.0.1 took 5ms a long padding tail here";
    let second = "2026-08-25T10:00:01Z INFO hc 10.0.0.2 took 6ms a long padding tail here";
    let other = "2026-08-25T10:00:01Z ERROR a completely different line of its own length";
    let lines: Vec<String> = [first, second, other, first, second, other]
        .iter()
        .map(|line| line.to_string())
        .collect();
    let payload = lines.join(r"\n").into_bytes();
    let case = Case {
        name: String::from("a mask-equal pair that stage five alone cannot see"),
        payload,
        options: resolve(&RawOptions::default()).expect("resolve"),
    };
    let span = &case.payload[first.len() + 2..2 * first.len() + 2];
    assert_ne!(span, &case.payload[..first.len()]);
    assert_eq!(
        mask::mask(&wsnorm::normalize(span)),
        mask::mask(&wsnorm::normalize(&case.payload[..first.len()])),
        "the two lines mask equal, so stage seven would fold them on the next pass"
    );
    let once = compress(&case);
    assert!(
        !once
            .commits
            .iter()
            .any(|commit| commit.kind == CommitKind::Block),
        "the primitivity check must read the coarsest domain, not stage five's own: {:?}",
        once.commits
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last, commit.count))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        once.commits
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [
            (CommitKind::TemplatedBlock, 0, 1, 1),
            (CommitKind::TemplatedBlock, 3, 4, 1)
        ]
    );
    let second = compress(&again(&case, once.payload.clone(), 2));
    assert_eq!(second.payload, once.payload);
    assert_eq!(second.commits.len(), 0);
}

fn kind_name(kind: CommitKind) -> &'static str {
    match kind {
        CommitKind::ExactRun => "exact_run",
        CommitKind::WsRun => "ws_run",
        CommitKind::Block => "block",
        CommitKind::TemplateGroup => "template_group",
        CommitKind::TemplatedBlock => "templated_block",
    }
}

// ---------------------------------------------------------------- idempotence

#[test]
fn every_generated_payload_reaches_a_fixed_point() {
    let cases = corpus(2048, SEED ^ 0x33);
    let (mut compressed, mut markers) = (0usize, 0usize);
    for case in &cases {
        let once = compress(case);
        if once.commits.is_empty() {
            assert_eq!(once.payload, case.payload, "{}", case.name);
            continue;
        }
        compressed += 1;
        markers += once.commits.len();
        assert!(
            once.payload.len() < case.payload.len(),
            "{}: a commit did not shrink the payload",
            case.name
        );
        let second = compress(&again(case, once.payload.clone(), 2));
        if second.payload != once.payload {
            let commit = &second.commits[0];
            panic!(
                "{}: not a fixed point, the second pass committed {:?} over {:?} with anchor {:?}",
                case.name,
                commit.kind,
                show(&once.payload[commit.removed.clone()]),
                show(&once.payload[commit.anchor.clone()]),
            );
        }
        assert_eq!(
            second.stats.groups_collapsed, 0,
            "{}: the second pass claims a collapse it did not make",
            case.name
        );
        let third = compress(&again(case, second.payload.clone(), 3));
        assert_eq!(third.payload, once.payload, "{}", case.name);
    }
    assert_eq!(cases.len(), 2048);
    assert!(
        compressed * 5 >= cases.len() * 3,
        "only {compressed} of {} payloads compress: the fixed point claim is untested",
        cases.len()
    );
    assert!(markers >= 1000, "only {markers} markers");
}

// ---------------------------------------------------------------- ledger invariants

struct SpanClaims {
    start: usize,
    end: usize,
    style: MarkerStyle,
    units: Vec<Unit>,
    commits: Vec<Commit>,
}

fn claims_of(case: &Case, run: &Output) -> Vec<SpanClaims> {
    let located = locator::locate(&case.payload, case.options.scope_policy);
    located
        .spans
        .iter()
        .map(|span| {
            let bytes = &case.payload[span.start..span.end];
            let style = render::resolve_style(case.options.marker_style, bytes);
            let commits = run
                .commits
                .iter()
                .filter(|commit| {
                    span.start <= commit.removed.start && commit.removed.end <= span.end
                })
                .cloned()
                .collect();
            SpanClaims {
                start: span.start,
                end: span.end,
                style,
                units: stage1::split_span(bytes, style),
                commits,
            }
        })
        .collect()
}

#[test]
fn no_stage_commits_into_an_already_claimed_range() {
    let cases = corpus(512, SEED ^ 0x44);
    let (mut claims, mut spans_seen, mut units_seen) = (0usize, 0usize, 0usize);
    for case in &cases {
        let run = compress(case);
        if run.commits.is_empty() {
            continue;
        }
        for span in claims_of(case, &run) {
            units_seen += span.units.len();
            if span.commits.is_empty() {
                continue;
            }
            spans_seen += 1;
            let mut owner: Vec<Option<usize>> = vec![None; span.units.len()];
            for (at, commit) in span.commits.iter().enumerate() {
                assert!(
                    commit.last < span.units.len(),
                    "{}: {:?} indexes outside its span",
                    case.name,
                    commit.removed
                );
                for (index, slot) in owner
                    .iter_mut()
                    .enumerate()
                    .take(commit.last + 1)
                    .skip(commit.first)
                {
                    assert_eq!(
                        *slot, None,
                        "{}: {:?} claims unit {index}, already claimed",
                        case.name, commit.removed
                    );
                    assert!(
                        span.units[index].eligible,
                        "{}: an ineligible unit is inside {:?}",
                        case.name, commit.removed
                    );
                    *slot = Some(at);
                }
                for previous in &span.commits[..at] {
                    assert!(
                        commit.removed.end <= previous.removed.start
                            || previous.removed.end <= commit.removed.start,
                        "{}: {:?} overlaps {:?}",
                        case.name,
                        commit.removed,
                        previous.removed
                    );
                }
                claims += 1;
            }
            for (index, unit) in span.units.iter().enumerate() {
                match owner[index] {
                    Some(at) => {
                        let commit = &span.commits[at];
                        let at = span.start + unit.range.start;
                        let end = span.start + unit.range.end;
                        assert!(
                            at >= commit.removed.start && end <= commit.removed.end,
                            "{}: unit {index} is owned by {:?} but lies outside it",
                            case.name,
                            commit.removed
                        );
                    }
                    None => {
                        let at = span.start + unit.range.start;
                        let end = span.start + unit.range.end;
                        for commit in &span.commits {
                            assert!(
                                end <= commit.removed.start || at >= commit.removed.end,
                                "{}: an unclaimed unit lies inside {:?}",
                                case.name,
                                commit.removed
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(claims >= 200, "only {claims} claims");
    assert!(spans_seen > 200, "only {spans_seen} spans carried a commit");
    assert!(units_seen > 5_000, "only {units_seen} units");
}

fn is_joiner(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes == b"," {
        return true;
    }
    let mut at = 0;
    while at < bytes.len() {
        let len = match bytes.get(at) {
            Some(b'\\') if bytes.get(at + 1) == Some(&b'n') => 2,
            Some(b'\\') if bytes.get(at + 1) == Some(&b'u') && at + 6 <= bytes.len() => 6,
            _ => return false,
        };
        if len == 6 && !matches!(&bytes[at + 2..at + 6], b"000A" | b"000a") {
            return false;
        }
        at += len;
    }
    at == bytes.len()
}

#[test]
fn every_removed_range_is_the_member_union_plus_its_joiners() {
    let cases = corpus(512, SEED ^ 0x55);
    let (mut checked, mut units_seen, mut joiners) = (0usize, 0usize, 0usize);
    for case in &cases {
        let run = compress(case);
        for span in claims_of(case, &run) {
            let bytes = &case.payload[span.start..span.end];
            units_seen += span.units.len();
            let mut regions: Vec<Range<usize>> = Vec::new();
            let mut claims: Vec<&Commit> = Vec::new();
            for commit in &span.commits {
                let group = commit.first..commit.last + 1;
                let members = &span.units[group.clone()];
                let expected = removal_range(&span.units, group.clone());
                assert_eq!(
                    commit.removed,
                    span.start + expected.start..span.start + expected.end,
                    "{}: {:?} is not the union of {:?} and its joiners",
                    case.name,
                    commit.removed,
                    group
                );
                let member_bytes: usize = members.iter().map(|unit| unit.range.len()).sum();
                let gaps: usize = members
                    .windows(2)
                    .map(|pair| pair[1].range.start - pair[0].range.end)
                    .sum();
                assert_eq!(commit.removed.len(), member_bytes + gaps, "{}", case.name);
                assert!(gaps > 0, "{}", case.name);
                let anchor_end = span
                    .units
                    .iter()
                    .position(|unit| span.start + unit.range.end == commit.anchor.end)
                    .expect("the anchor ends on a unit boundary");
                assert!(commit.first <= anchor_end, "{}", case.name);
                assert_eq!(
                    commit.anchor,
                    span.start + removal_range(&span.units, commit.first..anchor_end + 1).start
                        ..commit.anchor.end,
                    "{}: the anchor is not a whole-unit prefix of the removed range",
                    case.name
                );
                assert!(
                    profitable(
                        commit.style,
                        commit.kind,
                        commit.count,
                        commit.anchor.len(),
                        commit.removed.len()
                    ),
                    "{}: {:?} is below the profitability threshold",
                    case.name,
                    commit.removed
                );
                assert_eq!(commit.style, span.style, "{}", case.name);
                claims.push(commit);
                checked += 1;
            }
            let mut index = 0usize;
            let mut at = 0usize;
            while index < span.units.len() {
                let unit = &span.units[index];
                let gap = &bytes[at..unit.range.start];
                assert!(
                    is_joiner(gap),
                    "{}: {gap:?} before unit {index} is not a joiner",
                    case.name
                );
                joiners += 1;
                match claims.iter().find(|commit| commit.first == index) {
                    Some(commit) => {
                        regions.push(
                            commit.removed.start - span.start..commit.removed.end - span.start,
                        );
                        at = commit.removed.end - span.start;
                        index = commit.last + 1;
                    }
                    None => {
                        regions.push(unit.range.clone());
                        at = unit.range.end;
                        index += 1;
                    }
                }
            }
            let tail = &bytes[at..];
            assert!(is_joiner(tail), "{}: {tail:?} is not a joiner", case.name);
            regions.sort_by_key(|range| range.start);
            let mut covered = 0usize;
            for region in &regions {
                assert!(region.start >= covered, "{}", case.name);
                covered = region.end;
            }
            assert_eq!(covered + tail.len(), span.end - span.start, "{}", case.name);
        }
    }
    assert!(checked >= 200, "only {checked} removed ranges");
    assert!(units_seen > 5_000, "only {units_seen} units");
    assert!(joiners > 1000, "only {joiners} joiners");
}

// ---------------------------------------------------------------- buffer reuse

#[test]
fn a_poisoned_reused_output_buffer_never_leaks_a_stale_byte() {
    let cases = corpus(320, SEED ^ 0x66);
    let mut order: Vec<usize> = (0..cases.len()).collect();
    let mut rng = Rng(SEED ^ 0x77);
    for at in (1..order.len()).rev() {
        order.swap(at, rng.below(at + 1));
    }
    let poisons = [0x00u8, 0xff, b'A', b'{', 0x7f];
    let mut out = Vec::new();
    let mut compressor = Api::new();
    let (mut committed, mut shorter, mut shrank, mut refused) = (0usize, 0usize, 0usize, 0usize);
    let mut previous = 0usize;
    for (at, index) in order.iter().enumerate() {
        let case = &cases[*index];
        out.clear();
        let poison = poisons[at % poisons.len()];
        out.resize(out.capacity().min(1 << 17), poison);
        let poisoned = out.len();
        api::reserve(&mut out, case.payload.len());
        let served = compressor.compress(&case.payload, &request(case), &mut out);
        let mut fresh = Vec::new();
        api::reserve(&mut fresh, case.payload.len());
        let cold = Api::new().compress(&case.payload, &request(case), &mut fresh);
        match (&served, &cold) {
            (Err(error), Err(other)) => {
                assert_eq!(
                    error, other,
                    "{}: the refusal is not a pure function",
                    case.name
                );
                assert!(
                    matches!(error, api::ApiError::Malformed),
                    "{}: refused with {error}",
                    case.name
                );
                assert!(
                    !json_ok(
                        case.payload
                            .strip_prefix(&[0xef, 0xbb, 0xbf])
                            .unwrap_or(&case.payload)
                    ),
                    "{}: a valid document was refused",
                    case.name
                );
                refused += 1;
                continue;
            }
            (Ok(_), Ok(_)) => {}
            _ => panic!(
                "{}: one buffer served the request and the other refused it",
                case.name
            ),
        }
        let stats = served.expect("served");
        let clean = cold.expect("served");
        assert_eq!(
            out, fresh,
            "{}: a reused buffer changed the bytes",
            case.name
        );
        assert_eq!(out.len(), clean.bytes_out as usize, "{}", case.name);
        assert_eq!(
            stats.groups_collapsed, clean.groups_collapsed,
            "{}",
            case.name
        );
        assert_eq!(stats.bytes_in, clean.bytes_in, "{}", case.name);
        assert_eq!(
            out.iter().filter(|byte| **byte == poison).count(),
            fresh.iter().filter(|byte| **byte == poison).count(),
            "{}: a poisoned byte leaked into the response",
            case.name
        );
        if stats.groups_collapsed > 0 {
            committed += 1;
        }
        if out.len() < poisoned {
            shorter += 1;
        }
        if out.len() < previous && previous > 0 {
            shrank += 1;
        }
        previous = out.len();
    }
    assert!(committed > 100, "only {committed} of the cases compressed");
    assert!(
        refused * 4 < cases.len(),
        "only {refused} of {} cases were refused at all",
        cases.len()
    );
    assert!(
        shorter > 100,
        "only {shorter} responses were shorter than the poison fill: the reuse is untested"
    );
    assert!(
        shrank > 50,
        "only {shrank} transitions went from a larger response to a smaller one"
    );
}

// ---------------------------------------------------------------- determinism

struct Frozen(u64);

impl Clock for Frozen {
    fn now_ns(&self) -> u64 {
        self.0
    }
}

struct Counted(std::cell::Cell<u64>);

impl Clock for Counted {
    fn now_ns(&self) -> u64 {
        let next = self.0.get().wrapping_add(1_000_000_000);
        self.0.set(next);
        next
    }
}

struct Backwards(std::cell::Cell<u64>);

impl Clock for Backwards {
    fn now_ns(&self) -> u64 {
        let next = self.0.get();
        self.0.set(u64::MAX - next / 3);
        u64::MAX - next
    }
}

fn clock_for(repetition: usize) -> Compressor {
    match repetition % 4 {
        0 => Compressor::new(),
        1 => Compressor::with_clock(Frozen(0)),
        2 => Compressor::with_clock(Counted(std::cell::Cell::new(0))),
        _ => Compressor::with_clock(Backwards(std::cell::Cell::new(0))),
    }
}

#[test]
fn identical_input_yields_identical_output_under_every_option_and_clock() {
    let cases = corpus(48, SEED ^ 0x88);
    let mut runs = 0usize;
    for policy in [ScopePolicy::UserContent, ScopePolicy::UserAndTools] {
        for style in [MarkerStyle::Auto, MarkerStyle::Ascii, MarkerStyle::Unicode] {
            let options = resolve(&RawOptions {
                scope_policy: Some(policy),
                marker_style: Some(style),
                ..RawOptions::default()
            })
            .expect("resolve");
            let mut expected: Option<Vec<Vec<u8>>> = None;
            for repetition in 0..8 {
                let mut compressor = clock_for(repetition);
                let mut out = Vec::new();
                let mut digests = Vec::with_capacity(cases.len());
                for case in &cases {
                    out.clear();
                    compressor.compress(&case.payload, &options, &mut out);
                    digests.push(out.clone());
                }
                match &expected {
                    None => expected = Some(digests),
                    Some(first) => {
                        for (at, (got, want)) in digests.iter().zip(first).enumerate() {
                            assert_eq!(
                                got, want,
                                "{policy:?}/{style:?} repetition {repetition} case {at} differs"
                            );
                        }
                    }
                }
                runs += cases.len();
            }
        }
    }
    assert_eq!(runs, 6 * 8 * 48);
}

// ---------------------------------------------------------------- warm and cold

#[test]
fn a_warm_and_a_cold_compressor_agree_on_every_generated_payload() {
    let cases = corpus(64, SEED ^ 0x99);
    let options = resolve(&RawOptions::default()).expect("resolve");
    let mut warm = Compressor::new();
    let mut out = Vec::new();
    let mut first: BTreeMap<String, (Vec<u8>, Vec<Commit>)> = BTreeMap::new();
    for _ in 0..3 {
        for case in &cases {
            out.clear();
            warm.compress(&case.payload, &options, &mut out);
            let mut cold = Compressor::new();
            let mut cold_out = Vec::new();
            cold.compress(&case.payload, &options, &mut cold_out);
            assert_eq!(out, cold_out, "{}", case.name);
            let entry = (out.clone(), cold.commits().to_vec());
            match first.get(&case.name) {
                Some(expected) => assert_eq!(&entry, expected, "{}", case.name),
                None => {
                    first.insert(case.name.clone(), entry);
                }
            }
        }
    }
    let committed: usize = first.values().map(|(_, commits)| commits.len()).sum();
    assert!(committed > 50, "only {committed} commits");
}

#[test]
fn a_clock_can_never_move_a_single_output_byte() {
    let cases = corpus(64, SEED ^ 0xaa);
    let options = resolve(&RawOptions::default()).expect("resolve");
    let mut elapsed: BTreeSet<(u64, u64, u64)> = BTreeSet::new();
    for case in &cases {
        let mut out = Vec::new();
        let monotonic = Compressor::new().compress(&case.payload, &options, &mut out);
        let expected = out.clone();
        elapsed.insert((
            monotonic.elapsed_detect_ns,
            monotonic.elapsed_compact_ns,
            monotonic.elapsed_splice_ns,
        ));
        for repetition in 1..4 {
            let mut compressor = clock_for(repetition);
            out.clear();
            let stats = compressor.compress(&case.payload, &options, &mut out);
            assert_eq!(out, expected, "{} on repetition {repetition}", case.name);
            elapsed.insert((
                stats.elapsed_detect_ns,
                stats.elapsed_compact_ns,
                stats.elapsed_splice_ns,
            ));
        }
    }
    assert!(
        elapsed.contains(&(0, 0, 0)),
        "the frozen and the backwards clock must report zero elapsed time: {elapsed:?}"
    );
    assert!(
        elapsed.contains(&(1_000_000_000, 1_000_000_000, 1_000_000_000)),
        "the counted clock must report its own readings: {elapsed:?}"
    );
    assert!(
        elapsed.len() >= 3,
        "the injected clocks barely differ from the monotonic one: {elapsed:?}"
    );
}
