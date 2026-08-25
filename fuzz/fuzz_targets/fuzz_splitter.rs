#![no_main]
use libfuzzer_sys::fuzz_target;

// W0.4 stub: wire to unit splitter stages 1+1b (§4.4) in W1.2.
fuzz_target!(|data: &[u8]| {
    std::hint::black_box(data);
});
