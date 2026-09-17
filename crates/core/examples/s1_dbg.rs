use quantification_core::locator;

fn main() {
    let cases: Vec<(&str, usize)> = vec![
        ("{\"messages\":[{\"role\":\"user\",\"content\":\"a\"}]", 1),
        (
            "{\"messages\":[{\"role\":\"user\",\"content\":\"a\"},{\"role\":\"tool\",\"content\":\"b\"}",
            0,
        ),
    ];
    for (probe, want) in &cases {
        let spans = locator::locate(probe.as_bytes());
        println!("truncated: got {} want {}", spans.len(), want);
    }
}
