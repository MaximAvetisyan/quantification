use std::fmt::Write as _;

pub const TARGET_BYTES: usize = 8 << 20;

const SEED: u64 = 0x0BAD_C0DE_5EED_1234;

const DUMP_RECORDS: usize = 900;
const DUMP_LINES: usize = 1;
const EXACT_LINES: usize = 48;
const WS_LINES: usize = 12;
const TEMPLATE_LINES: usize = 480;
const TRACE_COPIES: usize = 8;
const REQ_LINES: usize = 5;
const REQ_COPIES: usize = 10;

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

struct Rng(u64);

impl Rng {
    fn new() -> Self {
        Self(SEED)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn hex(&mut self, digits: usize) -> String {
        let mut out = String::with_capacity(digits + 1);
        while out.len() < digits {
            let _ = write!(out, "{:016x}", self.next_u64());
        }
        out.truncate(digits);
        out
    }
}

pub fn log_heavy_chat(target: usize) -> Vec<u8> {
    let mut rng = Rng::new();
    let mut content = String::with_capacity(target + (1 << 18));
    let mut n = 0u32;
    let mut body = 0u32;
    while content.len() < target {
        push_body(&mut content, &mut rng, &mut n, &mut body);
    }
    let mut doc = String::with_capacity(content.len() + 96);
    doc.push_str(r#"{"model":"gpt-4o","messages":[{"role":"user","content":""#);
    doc.push_str(&content);
    doc.push_str(r#""}]}"#);
    doc.into_bytes()
}

fn push_body(out: &mut String, rng: &mut Rng, n: &mut u32, body: &mut u32) {
    let boot = format!(
        "2026-08-25T09:59:5{}Z INFO hc node-{} restarted worker=hc-{} epoch={}",
        *body % 10,
        *body,
        *body % 7,
        1700000000 + *body as u64
    );
    line(out, n, &boot);
    line(
        out,
        n,
        "2026-08-25T10:00:00Z INFO hc warm cache loaded shards=64 region=eu-west-1",
    );
    for _ in 0..EXACT_LINES {
        line(out, n, EXACT_CORE);
    }
    for at in 0..WS_LINES {
        let pad = match at % 4 {
            0 => format!("  {WS_CORE}"),
            1 => format!("{WS_CORE}  "),
            2 => format!("\t{WS_CORE}"),
            _ => format!(" {WS_CORE} "),
        };
        line(out, n, &pad);
    }
    for _ in 0..TEMPLATE_LINES {
        line(out, n, &template_line(rng));
    }
    for _ in 0..TRACE_COPIES {
        for trace in TRACE {
            line(out, n, trace);
        }
    }
    for _ in 0..REQ_COPIES {
        for at in 0..REQ_LINES {
            line(out, n, &request_line(rng, at));
        }
    }
    for _ in 0..DUMP_LINES {
        dump(out, rng, *body);
        newline(out, n);
    }
    *body += 1;
}

fn template_line(rng: &mut Rng) -> String {
    format!(
        "2026-08-25T10:{:02}:{:02}Z INFO hc req {} from 10.{}.{}.{} took {}ms bytes={} trace={}",
        rng.below(60),
        rng.below(60),
        uuid(rng),
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
        1 => format!("<-- 200 OK (req {})", uuid(rng)),
        2 => format!(
            "    handler=orders.charge user={} span={}",
            uuid(rng),
            rng.hex(32)
        ),
        3 => format!("    db.query=\"SELECT * FROM orders WHERE id={id}\" rows={id}"),
        _ => format!("<-- 201 Created in {dur}ms"),
    }
}

fn uuid(rng: &mut Rng) -> String {
    let h = rng.hex(32);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn dump(out: &mut String, rng: &mut Rng, body: u32) {
    let mut record = String::with_capacity(128);
    out.push('[');
    for at in 0..DUMP_RECORDS {
        if at > 0 {
            out.push(',');
        }
        let _ = write!(
            record,
            r#"{{"id":"{}","lvl":{},"msg":"node \u000A {:04} ready\"","p":{}}}"#,
            rng.hex(16),
            rng.below(8),
            at,
            (body as u64 + 1) * 1000 + at as u64,
        );
        escape_into(out, &record);
        record.clear();
    }
    out.push(']');
}

fn line(out: &mut String, n: &mut u32, text: &str) {
    escape_into(out, text);
    newline(out, n);
}

fn newline(out: &mut String, n: &mut u32) {
    *n += 1;
    match *n % 4 {
        0 => out.push_str("\\u000A"),
        2 => out.push_str("\\u000a"),
        _ => out.push_str("\\n"),
    }
}

fn escape_into(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
}
