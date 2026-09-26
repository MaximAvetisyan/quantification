use quantification_core::spike::{Role, locator};

fn check(label: &str, cond: bool) {
    if !cond {
        println!("FAIL {label}");
        std::process::exit(1);
    }
    println!("ok {label}");
}

fn main() {
    let payloads = quantification_core::benches::build_payloads();
    let big = &payloads[0].payload;
    let spans = locator::locate(big);
    check("8mib single span", spans.len() == 1);
    check("8mib span class user", spans[0].role == Role::User);
    let inner = &big[spans[0].start..spans[0].end];
    check("span starts after content quote", inner[0] != b'"');
    check("span ends before closing quote", big[spans[0].end] == b'"');

    let multi = b"{\"messages\":[{\"role\":\"user\",\"content\":\"aaa\"},{\"role\":\"tool\",\"content\":\"bbb\"},{\"role\":\"assistant\",\"content\":\"ccc\"}]}";
    let spans = locator::locate(multi);
    check("multi message span count", spans.len() == 2);
    check("span0 user", spans[0].role == Role::User);
    check("span1 tool", spans[1].role == Role::Tool);
    check("assistant span excluded", spans.len() == 2);
    check(
        "span0 bytes",
        &multi[spans[0].start..spans[0].end] == b"aaa",
    );
    check(
        "span1 bytes",
        &multi[spans[1].start..spans[1].end] == b"bbb",
    );

    let malformed: &[&[u8]] = &[
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"unterminated}",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\x01bad\"}]}",
        b"{\"messages\":[",
        b"not json at all",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"a\"}",
    ];
    for (i, m) in malformed.iter().enumerate() {
        let spans = locator::locate(m);
        check("malformed degrades to zero spans", spans.is_empty());
        let _ = i;
    }

    let ws = b"{ \"messages\" : [ { \"role\" : \"user\" , \"content\" : \"abc\" } ] }";
    let spans = locator::locate(ws);
    check(
        "pretty whitespace handled",
        spans.len() == 1 && &ws[spans[0].start..spans[0].end] == b"abc",
    );

    let bom = [0xEFu8, 0xBB, 0xBF]
        .iter()
        .copied()
        .chain(ws.iter().copied())
        .collect::<Vec<u8>>();
    let spans = locator::locate(&bom);
    check("bom skipped", spans.len() == 1);
}
