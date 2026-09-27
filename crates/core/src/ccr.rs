use std::sync::{Arc, Mutex, MutexGuard};

use crate::fingerprint::fingerprint;
use crate::pipeline::{Clock, MonotonicClock};

pub const DEFAULT_TTL_NS: u64 = 900 * 1_000_000_000;
pub const DEFAULT_MAX_BYTES: usize = 67_108_864;

const HEX_CHARS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreId {
    pub hash: u128,
    pub len: usize,
}

impl RestoreId {
    pub fn of(original: &[u8]) -> Self {
        Self {
            hash: fingerprint(original),
            len: original.len(),
        }
    }

    pub fn parse(id: &str) -> Option<Self> {
        let (hash, len) = id.split_once(':')?;
        if hash.len() != HEX_CHARS
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        if len.is_empty() || !len.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if len.len() > 1 && len.starts_with('0') {
            return None;
        }
        Some(Self {
            hash: u128::from_str_radix(hash, 16).ok()?,
            len: len.parse().ok()?,
        })
    }
}

impl std::fmt::Display for RestoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:016x}{:016x}:{}",
            (self.hash >> 64) as u64,
            self.hash as u64,
            self.len
        )
    }
}

pub trait Sink {
    fn store(&mut self, original: &[u8], marker: &[u8], checksum: [u8; 4]) -> Option<RestoreId>;
}

struct Entry {
    id: RestoreId,
    original: Vec<u8>,
    cost: usize,
    stored_at_ns: u64,
}

pub struct Store {
    clock: Box<dyn Clock + Send + Sync>,
    ttl_ns: u64,
    max_bytes: usize,
    bytes: usize,
    entries: Vec<Entry>,
}

impl Store {
    pub fn new(ttl_ns: u64, max_bytes: usize) -> Self {
        Self::with_clock(MonotonicClock::new(), ttl_ns, max_bytes)
    }

    pub fn with_clock(
        clock: impl Clock + Send + Sync + 'static,
        ttl_ns: u64,
        max_bytes: usize,
    ) -> Self {
        Self {
            clock: Box::new(clock),
            ttl_ns,
            max_bytes,
            bytes: 0,
            entries: Vec::new(),
        }
    }

    pub fn insert(
        &mut self,
        id: RestoreId,
        original: Vec<u8>,
        marker: Vec<u8>,
        _checksum: [u8; 4],
    ) -> bool {
        if let Some(at) = self.entries.iter().position(|entry| entry.id == id) {
            if self.entries[at].original != original {
                return false;
            }
            self.entries.remove(at);
        }
        let cost = original.len() + marker.len();
        if cost > self.max_bytes || self.ttl_ns == 0 {
            return false;
        }
        let now = self.clock.now_ns();
        self.expire(now);
        while self.bytes + cost > self.max_bytes && !self.entries.is_empty() {
            let gone = self.entries.remove(0);
            self.bytes -= gone.cost;
        }
        self.entries.push(Entry {
            id,
            original,
            cost,
            stored_at_ns: now,
        });
        self.bytes += cost;
        true
    }

    pub fn restore(&self, _payload: Option<&[u8]>, id: &str) -> Option<Vec<u8>> {
        let id = RestoreId::parse(id)?;
        let entry = self.entries.iter().find(|entry| entry.id == id)?;
        if self.expired(entry) {
            return None;
        }
        if entry.original.len() != id.len || fingerprint(&entry.original) != id.hash {
            return None;
        }
        Some(entry.original.clone())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn expired(&self, entry: &Entry) -> bool {
        Self::expired_at(entry, self.clock.now_ns(), self.ttl_ns)
    }

    fn expired_at(entry: &Entry, now: u64, ttl_ns: u64) -> bool {
        now.saturating_sub(entry.stored_at_ns) >= ttl_ns
    }

    fn expire(&mut self, now: u64) {
        let mut at = 0;
        while at < self.entries.len() {
            if Self::expired_at(&self.entries[at], now, self.ttl_ns) {
                let gone = self.entries.remove(at);
                self.bytes -= gone.cost;
            } else {
                at += 1;
            }
        }
    }
}

impl Sink for Store {
    fn store(&mut self, original: &[u8], marker: &[u8], checksum: [u8; 4]) -> Option<RestoreId> {
        let id = RestoreId::of(original);
        self.insert(id, original.to_vec(), marker.to_vec(), checksum)
            .then_some(id)
    }
}

#[derive(Clone)]
pub struct Shared {
    store: Arc<Mutex<Store>>,
}

impl Shared {
    pub fn new(ttl_ns: u64, max_bytes: usize) -> Self {
        Self::with_clock(MonotonicClock::new(), ttl_ns, max_bytes)
    }

    pub fn with_clock(
        clock: impl Clock + Send + Sync + 'static,
        ttl_ns: u64,
        max_bytes: usize,
    ) -> Self {
        Self {
            store: Arc::new(Mutex::new(Store::with_clock(clock, ttl_ns, max_bytes))),
        }
    }

    pub fn insert(
        &self,
        id: RestoreId,
        original: Vec<u8>,
        marker: Vec<u8>,
        checksum: [u8; 4],
    ) -> bool {
        lock(&self.store).insert(id, original, marker, checksum)
    }

    pub fn put(&self, original: &[u8], marker: &[u8], checksum: [u8; 4]) -> Option<RestoreId> {
        lock(&self.store).store(original, marker, checksum)
    }

    pub fn restore(&self, payload: Option<&[u8]>, id: &str) -> Option<Vec<u8>> {
        lock(&self.store).restore(payload, id)
    }

    pub fn len(&self) -> usize {
        lock(&self.store).len()
    }

    pub fn is_empty(&self) -> bool {
        lock(&self.store).is_empty()
    }

    pub fn bytes(&self) -> usize {
        lock(&self.store).bytes()
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_NS, DEFAULT_MAX_BYTES)
    }
}

impl Sink for Shared {
    fn store(&mut self, original: &[u8], marker: &[u8], checksum: [u8; 4]) -> Option<RestoreId> {
        self.put(original, marker, checksum)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct Now(AtomicU64);

    impl Now {
        fn at(ns: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(ns)))
        }

        fn set(&self, ns: u64) {
            self.0.store(ns, Ordering::Relaxed);
        }
    }

    impl Clock for Now {
        fn now_ns(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl Clock for Arc<Now> {
        fn now_ns(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn id_of(bytes: &[u8]) -> String {
        RestoreId::of(bytes).to_string()
    }

    #[test]
    fn the_id_is_thirty_two_lowercase_hex_and_a_decimal_length() {
        for bytes in [
            &b""[..],
            b"a",
            b"2026-08-25T20:00:01Z INFO hc ok",
            &[0u8; 4096],
        ] {
            let id = id_of(bytes);
            let (hash, len) = id.split_once(':').expect("one colon");
            assert_eq!(hash.len(), 32);
            assert!(
                hash.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert_eq!(len.parse::<usize>().expect("a length"), bytes.len());
            assert_eq!(RestoreId::parse(&id), Some(RestoreId::of(bytes)));
            assert_eq!(RestoreId::of(bytes).len, bytes.len());
        }
        assert_eq!(id_of(b"ab").len(), 34);
    }

    #[test]
    fn a_tampered_id_is_never_an_id() {
        let original = b"ERROR timeout\nERROR timeout";
        let id = id_of(original);
        let (hash, len) = id.split_once(':').expect("one colon");
        let (hash, len) = (hash.to_string(), len.to_string());
        let upper = hash.to_uppercase();
        for garbage in [
            String::new(),
            String::from("garbage"),
            id.replace(':', ""),
            format!("{id}:4"),
            id[..31].to_string(),
            format!("{}g{len}", &hash[..1]),
            format!("{upper}:{len}"),
            format!("{hash}:0{len}"),
            format!("{hash}:-3"),
            format!("{hash}:"),
            format!("{id}\n"),
            format!("{id}:{len}"),
        ] {
            assert_eq!(RestoreId::parse(&garbage), None, "{garbage}");
        }
        assert_eq!(RestoreId::parse(&id), Some(RestoreId::of(original)));
    }

    #[test]
    fn an_entry_whose_bytes_disagree_with_its_key_is_a_miss() {
        let mut store = Store::with_clock(Now::at(0), 1_000_000_000, 1 << 20);
        let marker = b"[... x2 identical abcd ...]";
        let original = b"ERROR timeout\nERROR timeout\nERROR timeout";
        let id = RestoreId::of(original);
        assert!(store.insert(
            id,
            b"something else entirely".to_vec(),
            marker.to_vec(),
            *b"abcd"
        ));
        assert_eq!(store.restore(None, &id.to_string()), None);
        assert_eq!(
            store.restore(Some(marker), &id.to_string()),
            None,
            "a payload is never authority: the entry itself disagrees with its key"
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_mutated_entry_is_caught_by_re_verification() {
        let mut store = Store::with_clock(Now::at(0), 1_000_000_000, 1 << 20);
        let original = b"ERROR timeout\nERROR timeout\nERROR timeout";
        assert!(
            store
                .store(original, b"[... x2 identical abcd ...]", *b"abcd")
                .is_some()
        );
        assert_eq!(
            store.restore(None, &id_of(original)),
            Some(original.to_vec())
        );
        store.entries[0].original[0] = b'X';
        assert_eq!(
            store.restore(None, &id_of(original)),
            None,
            "the stored bytes no longer hash to their key"
        );
    }

    #[test]
    fn a_collision_never_replaces_a_live_entry() {
        let mut store = Store::with_clock(Now::at(0), 1_000_000_000, 1 << 20);
        let first = b"first original bytes";
        let second = b"a different original";
        let id = RestoreId::of(first);
        assert!(store.insert(id, first.to_vec(), b"m".to_vec(), *b"aaaa"));
        assert!(!store.insert(id, second.to_vec(), b"m".to_vec(), *b"aaaa"));
        assert_eq!(store.restore(None, &id.to_string()), Some(first.to_vec()));
        assert_eq!(store.store(first, b"m", *b"aaaa"), Some(id));
        assert_eq!(store.len(), 1, "the same original refreshes its entry");
    }

    #[test]
    fn the_ttl_and_the_byte_bound_are_injected_not_slept() {
        let clock = Now::at(0);
        let mut store = Store::with_clock(clock.clone(), 10, 1 << 20);
        let first = b"the first original";
        let second = b"the second original";
        assert!(store.store(first, b"m1", *b"1111").is_some());
        clock.set(5);
        assert!(store.store(second, b"m2", *b"2222").is_some());
        assert_eq!(store.len(), 2);
        clock.set(9);
        assert_eq!(
            store.restore(None, &id_of(first)),
            Some(first.to_vec()),
            "inside the ttl"
        );
        clock.set(10);
        assert_eq!(store.restore(None, &id_of(first)), None, "expired");
        assert_eq!(store.restore(None, &id_of(second)), Some(second.to_vec()));

        let mut bounded = Store::with_clock(clock.clone(), 1_000_000_000, 40);
        assert!(bounded.store(first, b"m1", *b"1111").is_some());
        assert!(bounded.store(second, b"m2", *b"2222").is_some());
        assert_eq!(bounded.len(), 1, "the bound evicts the oldest insert");
        assert_eq!(bounded.restore(None, &id_of(second)), Some(second.to_vec()));
        assert_eq!(bounded.restore(None, &id_of(first)), None);
        let huge = vec![b'x'; 128];
        assert_eq!(
            bounded.store(&huge, b"m", *b"3333"),
            None,
            "an entry larger than the whole bound is never stored"
        );
        assert_eq!(bounded.len(), 1, "a refused insert changes nothing");
        assert_eq!(bounded.restore(None, &id_of(&huge)), None);
    }

    #[test]
    fn the_id_is_the_authority_and_the_payload_is_only_context() {
        let mut store = Store::with_clock(Now::at(0), 1_000_000_000, 1 << 20);
        let original = b"ERROR timeout\nERROR timeout\nERROR timeout";
        let marker = b"[... x2 identical abcd ...]";
        let compressed = b"{\"content\":\"ERROR timeout[... x2 identical abcd ...]\"}";
        assert!(store.store(original, marker, *b"abcd").is_some());
        let unicode = "{\"content\":\"ERROR timeout\u{27ea}\u{d7}2 identical \u{b7}abcd\u{27eb}\"}"
            .as_bytes();
        for payload in [
            None,
            Some(&b""[..]),
            Some(&compressed[..]),
            Some(unicode),
            Some(&b"{\"content\":\"nothing to do with it\"}"[..]),
            Some(&b"[... x2 identical wxyz ...]"[..]),
        ] {
            assert_eq!(
                store.restore(payload, &id_of(original)),
                Some(original.to_vec()),
                "the id addresses its own original whatever the caller's payload says"
            );
        }
        for wrong in [
            "00000000000000000000000000000000:0",
            "garbage",
            "bccde1936da3c9e2627e4635690aa9c2:157",
        ] {
            assert_eq!(
                store.restore(Some(&compressed[..]), wrong),
                None,
                "{wrong} is a miss"
            );
        }
    }

    #[test]
    fn one_original_stored_under_many_markers_restores_every_time() {
        let original = b"ERROR timeout\nERROR timeout\nERROR timeout";
        let id = RestoreId::of(original);
        let printed = id_of(original);
        let markers: [&[u8]; 3] = [
            b"[... x2 identical abcd ...]".as_slice(),
            "\u{27ea}\u{d7}2 identical \u{b7}abcd\u{27eb}".as_bytes(),
            b"[... block x2 1234 ...]".as_slice(),
        ];
        let mut forwards = Store::with_clock(Now::at(0), 1_000_000_000, 1 << 20);
        let mut backwards = Store::with_clock(Now::at(0), 1_000_000_000, 1 << 20);
        for (at, marker) in markers.iter().enumerate() {
            let other = markers.len() - 1 - at;
            assert_eq!(forwards.store(original, marker, *b"abcd"), Some(id));
            assert_eq!(
                backwards.store(original, markers[other], *b"abcd"),
                Some(id)
            );
        }
        for store in [&forwards, &backwards] {
            assert_eq!(store.len(), 1, "one content address, one entry");
            assert_eq!(store.restore(None, &printed), Some(original.to_vec()));
            for marker in markers {
                let payload = format!("{{\"content\":\"{}\"}}", String::from_utf8_lossy(marker));
                assert_eq!(
                    store.restore(Some(payload.as_bytes()), &printed),
                    Some(original.to_vec()),
                    "the id addresses its own original whatever was stored under it"
                );
            }
        }
    }
}
