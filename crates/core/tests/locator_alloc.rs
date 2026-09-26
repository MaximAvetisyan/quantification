use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use quantification_core::config::ScopePolicy;
use quantification_core::locator::{Span, locate_into};
use quantification_core::sniff::Schema;

struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const MESSAGES: usize = 400;
const LINES: usize = 40;
const SPAN_CAPACITY: usize = 4_096;

fn many_messages() -> Vec<u8> {
    let mut doc = String::from(r#"{"model":"gpt-4o","messages":["#);
    for m in 0..MESSAGES {
        if m > 0 {
            doc.push(',');
        }
        let role = if m % 3 == 0 { "tool" } else { "user" };
        doc.push_str(&format!(r#"{{"role":"{role}","content":""#));
        for line in 0..LINES {
            if line > 0 {
                doc.push_str(r"\n");
            }
            doc.push_str(&format!(
                r#"2026-08-25T10:00:0{line}Z INFO m{m} 10.0.0.{line} ok \u0041 \"q\" \\path"#
            ));
        }
        doc.push_str("\"}");
    }
    doc.push_str("]}");
    doc.into_bytes()
}

fn one_big_span() -> Vec<u8> {
    let mut doc = String::from(r#"{"messages":[{"role":"user","content":""#);
    for line in 0..20_000 {
        if line > 0 {
            doc.push_str(r"\n");
        }
        doc.push_str(
            r#"2026-08-25T10:00:01Z INFO big 10.0.0.1 ok \t \\\"quoted\\\" \\\\slash\\\\ "#,
        );
    }
    doc.push_str("\"}]}");
    doc.into_bytes()
}

fn counted(schema: Schema, policy: ScopePolicy, payload: &[u8], out: &mut Vec<Span>) -> usize {
    let before = ALLOCS.load(Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let noop = locate_into(payload, schema, policy, out);
    ARMED.store(false, Ordering::Relaxed);
    let after = ALLOCS.load(Ordering::Relaxed);
    assert_eq!(noop, None);
    assert_eq!(
        out.capacity(),
        SPAN_CAPACITY,
        "the output vec must never grow"
    );
    after - before
}

#[test]
fn the_locator_hot_loop_is_allocation_free() {
    let many = many_messages();
    let big = one_big_span();
    let mut out: Vec<Span> = Vec::with_capacity(SPAN_CAPACITY);
    let mut alloc_total = 0usize;

    let tools = MESSAGES.div_ceil(3);
    let users = MESSAGES - tools;
    alloc_total += counted(Schema::Chat, ScopePolicy::UserAndTools, &many, &mut out);
    assert_eq!(out.len(), MESSAGES);
    assert_eq!(alloc_total, 0, "many-message hot loop allocated");

    out.clear();
    alloc_total += counted(Schema::Chat, ScopePolicy::UserContent, &many, &mut out);
    assert_eq!(out.len(), users);
    assert_eq!(alloc_total, 0, "user_content hot loop allocated");

    out.clear();
    alloc_total += counted(Schema::Chat, ScopePolicy::UserAndTools, &big, &mut out);
    assert_eq!(out.len(), 1);
    assert!(big.len() > 1_000_000);
    assert_eq!(alloc_total, 0, "single huge span hot loop allocated");

    out.clear();
    alloc_total += counted(
        Schema::Responses,
        ScopePolicy::UserAndTools,
        &many,
        &mut out,
    );
    assert_eq!(alloc_total, 0, "responses scan allocated");

    out.clear();
    alloc_total += counted(Schema::Messages, ScopePolicy::UserAndTools, &many, &mut out);
    assert_eq!(alloc_total, 0, "messages scan allocated");

    out.clear();
    alloc_total += counted(Schema::Text, ScopePolicy::UserContent, &big, &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(alloc_total, 0, "text schema allocated");

    assert_eq!(out.capacity(), SPAN_CAPACITY);
}
