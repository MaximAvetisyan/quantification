#[path = "../../core/tests/adversarial_fixtures.rs"]
mod adversarial;

use std::fmt::Write as _;

use quantification_core::sniff::Schema;

pub const LOG_HEAVY_TARGET: usize = 512 * 1024;
pub const LOG_HEAVY_SMALL: usize = 128 * 1024;
pub const SEED: u64 = 0x0E4A_1000_0000_0006;

const GOLDEN: &[&str] = &[
    "schemas/chat-minified.json",
    "schemas/chat-pretty.json",
    "schemas/messages-minified.json",
    "schemas/messages-pretty.json",
    "schemas/responses-minified.json",
    "schemas/responses-pretty.json",
    "schemas/text-plain.txt",
    "shapes/anthropic-system-top.json",
    "shapes/anthropic-tool-result.json",
    "shapes/chat-content-null.json",
    "shapes/chat-mixed-parts.json",
    "shapes/responses-function-call-output.json",
    "shapes/responses-input-string.json",
    "shapes/sniff-overlap-chat-responses.json",
    "edges/bom-chat.json",
    "edges/dup-keys-last-wins.json",
    "edges/escaped-structural-keys.json",
    "edges/newlines-u000a-only.json",
    "edges/prior-markers.json",
    "edges/profitability-below-threshold.json",
    "edges/single-line-tool-dump-overcap.json",
    "edges/single-line-tool-dump-small.json",
    "edges/stage1b-no-separator-overcap.json",
    "edges/stage1b-record-len-16383.json",
    "edges/stage1b-record-len-16384.json",
    "edges/stage1b-record-len-16385.json",
];

const TRACE: &[&str] = &[
    "panic: runtime error: index out of range [7] with length 3",
    "    at parseRow (/srv/app/store/scan.go:214)",
    "    at readFrame (/srv/app/store/scan.go:88)",
    "    at serve (/srv/app/http/serve.go:41)",
    "    at main.main (/srv/app/main.go:12)",
    "goroutine 17 [running]:",
];

const WS_CORE: &str =
    "2026-08-25T10:00:01Z INFO hc cache miss key=\"session:4471\" backend=redis pool=8";
const EXACT_CORE: &str = "2026-08-25T10:00:00Z INFO hc request completed path=\"/srv/app/handlers.go\" status=200 dur=12ms";
const SUMMARIES: &[&str] = &["hc", "db", "api"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stratum {
    LogHeavy,
    Golden,
    Adversarial,
}

impl Stratum {
    pub const ALL: [Stratum; 3] = [Self::LogHeavy, Self::Golden, Self::Adversarial];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LogHeavy => "log_heavy",
            Self::Golden => "golden",
            Self::Adversarial => "adversarial",
        }
    }
}

pub struct Payload {
    pub name: String,
    pub stratum: Stratum,
    pub bytes: Vec<u8>,
}

impl Payload {
    pub fn schema(&self) -> Option<Schema> {
        quantification_core::sniff::sniff(&self.bytes)
    }
}

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn hex(&mut self, digits: usize) -> String {
        let mut out = String::with_capacity(digits + 1);
        while out.len() < digits {
            let _ = write!(out, "{:016x}", self.next_u64());
        }
        out.truncate(digits);
        out
    }

    pub fn uuid(&mut self) -> String {
        let h = self.hex(32);
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
    }
}

pub fn log_heavy() -> Vec<Payload> {
    let mut out = Vec::new();
    for schema in [
        Schema::Chat,
        Schema::Responses,
        Schema::Messages,
        Schema::Text,
    ] {
        for (label, target) in [("512k", LOG_HEAVY_TARGET), ("128k", LOG_HEAVY_SMALL)] {
            let seed = SEED ^ ((schema.as_str().len() as u64) << 32) ^ target as u64;
            out.push(Payload {
                name: format!("log_heavy/{}/{}", schema.as_str(), label),
                stratum: Stratum::LogHeavy,
                bytes: build(schema, target, seed),
            });
        }
    }
    out
}

pub fn golden() -> Vec<Payload> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures");
    GOLDEN
        .iter()
        .map(|rel| {
            let path = root.join(rel);
            Payload {
                name: format!("golden/{rel}"),
                stratum: Stratum::Golden,
                bytes: std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
            }
        })
        .collect()
}

pub fn adversarial() -> Vec<Payload> {
    adversarial::gate_suite()
        .into_iter()
        .map(|case| Payload {
            name: case.name.to_string(),
            stratum: Stratum::Adversarial,
            bytes: case.payload,
        })
        .collect()
}

pub fn full() -> Vec<Payload> {
    let mut out = log_heavy();
    out.extend(golden());
    out.extend(adversarial());
    out
}

pub fn build(schema: Schema, target: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut body = String::with_capacity(target + (1 << 16));
    while body.len() < target {
        push_body(&mut body, &mut rng);
    }
    match schema {
        Schema::Text => body.into_bytes(),
        Schema::Chat => wrap_chat(&body),
        Schema::Messages => wrap_messages(&body),
        Schema::Responses => wrap_responses(&body),
    }
}

fn wrap_chat(body: &str) -> Vec<u8> {
    let mut out = String::with_capacity(body.len() + 96);
    out.push_str(r#"{"model":"gpt-4o","messages":[{"role":"user","content":""#);
    escape_into(&mut out, body);
    out.push_str(r#""}]}"#);
    out.into_bytes()
}

fn wrap_messages(body: &str) -> Vec<u8> {
    let mut out = String::with_capacity(body.len() + 128);
    out.push_str(
        r#"{"model":"claude-sonnet-4","max_tokens":1024,"messages":[{"role":"user","content":""#,
    );
    escape_into(&mut out, body);
    out.push_str(r#""}]}"#);
    out.into_bytes()
}

fn wrap_responses(body: &str) -> Vec<u8> {
    let mut out = String::with_capacity(body.len() + 160);
    out.push_str(
        r#"{"model":"gpt-4o","input":[{"type":"message","role":"user","content":[{"type":"text","text":""#,
    );
    escape_into(&mut out, body);
    out.push_str(r#""}]}]}"#);
    out.into_bytes()
}

fn escape_into(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
}

fn push_body(out: &mut String, rng: &mut Rng) {
    let level = SUMMARIES[rng.below(SUMMARIES.len())];
    out.push_str(&format!(
        "2026-08-25T09:59:5{}Z INFO {level} node-{} restarted worker=hc-{} epoch={}\n",
        rng.below(10),
        rng.below(64),
        rng.below(7),
        1_700_000_000u64 + rng.below(1000) as u64
    ));
    out.push_str(&format!(
        "2026-08-25T10:00:00Z INFO {level} warm cache loaded shards=64 region=eu-west-1\n"
    ));
    for _ in 0..48 {
        out.push_str(EXACT_CORE);
        out.push('\n');
    }
    for at in 0..12 {
        let pad = match at % 4 {
            0 => format!("  {WS_CORE}"),
            1 => format!("{WS_CORE}  "),
            2 => format!("\t{WS_CORE}"),
            _ => format!(" {WS_CORE} "),
        };
        out.push_str(&pad);
        out.push('\n');
    }
    for _ in 0..480 {
        out.push_str(&template_line(rng, level));
        out.push('\n');
    }
    for _ in 0..8 {
        for line in TRACE {
            out.push_str(line);
            out.push('\n');
        }
    }
    for _ in 0..10 {
        for at in 0..5 {
            out.push_str(&request_line(rng, at));
            out.push('\n');
        }
    }
    dump(out, rng);
    out.push('\n');
}

fn template_line(rng: &mut Rng, level: &str) -> String {
    let lvl = if rng.below(9) == 0 { "WARN" } else { "INFO" };
    format!(
        "2026-08-25T10:{:02}:{:02}Z {lvl} {level} req {} from 10.{}.{}.{} took {}ms bytes={} trace={}",
        rng.below(60),
        rng.below(60),
        rng.uuid(),
        rng.below(256),
        rng.below(256),
        rng.below(256),
        rng.below(900) + 1,
        rng.below(900_000) + 1_000,
        rng.hex(32),
    )
}

fn request_line(rng: &mut Rng, at: usize) -> String {
    let id = rng.below(90_000) + 1_000;
    let dur = rng.below(900) + 1;
    match at {
        0 => format!("--> POST /v1/orders/{id} 200 in {dur}ms"),
        1 => format!("<-- 200 OK (req {})", rng.uuid()),
        2 => format!(
            "    handler=orders.charge user={} span={}",
            rng.uuid(),
            rng.hex(32)
        ),
        3 => format!("    db.query=\"SELECT * FROM orders WHERE id={id}\" rows={id}"),
        _ => format!("<-- 201 Created in {dur}ms"),
    }
}

fn dump(out: &mut String, rng: &mut Rng) {
    out.push('[');
    for at in 0..900 {
        if at > 0 {
            out.push(',');
        }
        let record = format!(
            r#"{{"id":"{}","lvl":{},"msg":"node \u000A {:04} ready\"","p":{}}}"#,
            rng.hex(16),
            rng.below(8),
            at,
            1000 + at
        );
        escape_into(out, &record);
    }
    out.push(']');
}
