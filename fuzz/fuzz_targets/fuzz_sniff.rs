#![no_main]
use libfuzzer_sys::fuzz_target;

// W0.4 stub: wire to schema sniff entry point in W1.1.
fuzz_target!(|data: &[u8]| {
    std::hint::black_box(data);
});
