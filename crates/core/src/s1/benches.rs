use crate::locator;

pub const TARGET_BYTES: usize = 8 << 20;

pub struct Case {
    pub name: &'static str,
    pub payload: Vec<u8>,
}

pub fn build_payloads() -> Vec<Case> {
    vec![
        Case {
            name: "escaped_chat_lines",
            payload: gen_escaped_chat_lines(TARGET_BYTES),
        },
        Case {
            name: "escaped_tool_dumps",
            payload: gen_escaped_tool_dumps(TARGET_BYTES),
        },
    ]
}

pub fn run(payload: &[u8], reps: usize) -> std::time::Duration {
    let mut acc = std::time::Duration::ZERO;
    for _ in 0..reps {
        let start = std::time::Instant::now();
        let spans = locator::locate(payload);
        acc += start.elapsed();
        std::hint::black_box(&spans);
    }
    acc / reps as u32
}

pub fn span_count(payload: &[u8]) -> usize {
    locator::locate(payload).len()
}

fn gen_escaped_chat_lines(target: usize) -> Vec<u8> {
    let mut line = String::from("2026-08-25T10:00:01Z INFO hc 10.0.0.1 ok");
    for k in 0..64 {
        line.push_str(&format!(
            " k\\\"{k}\\\"=\\u000A\\t\\\\path\\\\ {k:04} q=\\\"s\\\" "
        ));
    }
    line.push_str("end\\\"");
    let mut content = String::with_capacity(target);
    while content.len() < target {
        content.push_str(&line);
        content.push_str("\\n");
    }
    wrap_chat_user(&content)
}

fn gen_escaped_tool_dumps(target: usize) -> Vec<u8> {
    let mut dump = String::from("[");
    for k in 0..40 {
        let lvl = k % 8;
        let p = k * 37 % 997;
        if k > 0 {
            dump.push(',');
        }
        dump.push_str(&format!(
            "{{\\\"id\\\":\\\"{k:08x}\\\",\\\"lvl\\\":{lvl},\\\"msg\\\":\\\"node \\\\u000A {k:04} ready\\\\\\\"\\\",\\\"p\\\":{p}}}"
        ));
    }
    dump.push(']');
    let mut content = String::with_capacity(target);
    while content.len() < target {
        content.push_str(&dump);
        content.push_str("\\n");
    }
    wrap_chat_tool(&content)
}

fn wrap_chat_user(content: &str) -> Vec<u8> {
    let mut doc = String::with_capacity(content.len() + 96);
    doc.push_str("{\"model\":\"gpt-4o\",\"messages\":[");
    doc.push_str("{\"role\":\"user\",\"content\":\"");
    doc.push_str(content);
    doc.push_str("\"}]}");
    doc.into_bytes()
}

fn wrap_chat_tool(content: &str) -> Vec<u8> {
    let mut doc = String::with_capacity(content.len() + 96);
    doc.push_str("{\"model\":\"gpt-4o\",\"messages\":[");
    doc.push_str("{\"role\":\"tool\",\"tool_call_id\":\"c1\",\"content\":\"");
    doc.push_str(content);
    doc.push_str("\"}]}");
    doc.into_bytes()
}

pub fn build_and_report() {
    for Case { name, payload } in build_payloads() {
        for _ in 0..5 {
            std::hint::black_box(run(&payload, 1));
        }
        let reps = 40;
        let mut times = Vec::with_capacity(reps);
        for _ in 0..reps {
            times.push(run(&payload, 1));
        }
        times.sort();
        let p50 = times[reps / 2];
        let p99 = times[(reps * 99) / 100];
        let mb = payload.len() as f64 / 1_000_000.0;
        let p50_mbs = mb / p50.as_secs_f64();
        let p99_mbs = mb / p99.as_secs_f64();
        println!(
            "{name}: {} bytes, {} spans, p50 {p50:.2?} ({p50_mbs:.0} MB/s), p99 {p99:.2?} ({p99_mbs:.0} MB/s)",
            payload.len(),
            span_count(&payload),
        );
    }
}
