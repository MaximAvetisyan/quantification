use std::ops::Range;

use twox_hash::{XxHash3_64, XxHash3_128};

pub const HASH_SEED: u64 = 0;
pub const MIN_SLOTS: usize = 1 << 6;
pub const MAX_SLOTS: usize = 1 << 18;
pub const KEY_BYTES_PER_UNIT: usize = 16;

pub fn fingerprint(bytes: &[u8]) -> u128 {
    XxHash3_128::oneshot_with_seed(HASH_SEED, bytes)
}

pub fn marker_checksum(bytes: &[u8]) -> u16 {
    XxHash3_64::oneshot_with_seed(HASH_SEED, bytes) as u16
}

#[derive(Clone, Copy)]
struct Slot {
    hash: u128,
    key: usize,
    len: usize,
    rep: usize,
}

const EMPTY: Slot = Slot {
    hash: 0,
    key: 0,
    len: 0,
    rep: usize::MAX,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insert {
    New,
    Duplicate(usize),
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Miss {
    Absent,
    Hash,
    Length,
    Memcmp,
}

pub struct FingerprintTable {
    slots: Vec<Slot>,
    len: usize,
}

impl FingerprintTable {
    pub fn for_keys(key_bytes: usize) -> Self {
        let want = (key_bytes / KEY_BYTES_PER_UNIT).clamp(MIN_SLOTS, MAX_SLOTS);
        Self {
            slots: vec![EMPTY; want.next_power_of_two()],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    pub fn is_full(&self) -> bool {
        self.capped() && (self.len + 1) * 4 > self.slots.len() * 3
    }

    pub fn insert(&mut self, keys: &[u8], key: Range<usize>, rep: usize) -> Insert {
        let hash = fingerprint(&keys[key.clone()]);
        self.insert_hashed(keys, key, rep, hash)
    }

    pub(crate) fn insert_hashed(
        &mut self,
        keys: &[u8],
        key: Range<usize>,
        rep: usize,
        hash: u128,
    ) -> Insert {
        if let Some(found) = self.probe(keys, &key, hash).0 {
            return Insert::Duplicate(found);
        }
        if !self.capped() && (self.len + 1) * 4 > self.slots.len() * 3 {
            self.grow();
        }
        if (self.len + 1) * 4 > self.slots.len() * 3 {
            return Insert::Full;
        }
        self.place(hash, key.start, key.len(), rep);
        self.len += 1;
        Insert::New
    }

    pub fn find(&self, keys: &[u8], key: Range<usize>) -> Option<usize> {
        let hash = fingerprint(&keys[key.clone()]);
        self.find_hashed(keys, key, hash)
    }

    pub(crate) fn find_hashed(&self, keys: &[u8], key: Range<usize>, hash: u128) -> Option<usize> {
        self.probe(keys, &key, hash).0
    }

    fn capped(&self) -> bool {
        self.slots.len() >= MAX_SLOTS
    }

    fn start(&self, hash: u128) -> usize {
        hash as u64 as usize & (self.slots.len() - 1)
    }

    fn probe(&self, keys: &[u8], key: &Range<usize>, hash: u128) -> (Option<usize>, Miss) {
        let mut miss = Miss::Absent;
        let mut at = self.start(hash);
        loop {
            let slot = self.slots[at];
            if slot.rep == usize::MAX {
                return (None, miss);
            }
            if slot.len == key.len() {
                if slot.hash == hash {
                    if keys[slot.key..slot.key + slot.len] == keys[key.clone()] {
                        return (Some(slot.rep), Miss::Absent);
                    }
                    miss = miss.max(Miss::Memcmp);
                } else {
                    miss = miss.max(Miss::Hash);
                }
            } else {
                miss = miss.max(Miss::Length);
            }
            at = (at + 1) & (self.slots.len() - 1);
        }
    }

    fn place(&mut self, hash: u128, key: usize, len: usize, rep: usize) {
        let mut at = self.start(hash);
        while self.slots[at].rep != usize::MAX {
            at = (at + 1) & (self.slots.len() - 1);
        }
        self.slots[at] = Slot {
            hash,
            key,
            len,
            rep,
        };
    }

    fn grow(&mut self) {
        let grown = vec![EMPTY; self.slots.len() * 2];
        let old = std::mem::replace(&mut self.slots, grown);
        for slot in old {
            if slot.rep != usize::MAX {
                self.place(slot.hash, slot.key, slot.len, slot.rep);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[u8] = b"abc abd xyz abcx 0123456";

    fn range(needle: &[u8]) -> Range<usize> {
        let at = KEYS
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("key present");
        at..at + needle.len()
    }

    fn table_with_one() -> FingerprintTable {
        let mut table = FingerprintTable::for_keys(KEYS.len());
        assert_eq!(table.insert(KEYS, range(b"abc"), 7), Insert::New);
        table
    }

    #[test]
    fn verification_order_is_length_then_hash_then_memcmp() {
        let table = table_with_one();
        let hash = fingerprint(b"abc");
        assert_eq!(
            table.probe(KEYS, &range(b"abc"), hash),
            (Some(7), Miss::Absent)
        );
        assert_eq!(
            table.probe(KEYS, &range(b"abd"), hash),
            (None, Miss::Memcmp)
        );
        assert_eq!(
            table.probe(KEYS, &range(b"abcx"), hash),
            (None, Miss::Length)
        );
        let same_slot = hash ^ (1u128 << 64);
        assert_eq!(
            table.probe(KEYS, &range(b"xyz"), same_slot),
            (None, Miss::Hash)
        );
        assert_eq!(
            FingerprintTable::for_keys(0).probe(KEYS, &range(b"abc"), hash),
            (None, Miss::Absent)
        );
    }

    #[test]
    fn memcmp_mismatch_keeps_both_keys_findable() {
        let mut table = table_with_one();
        let hash = fingerprint(b"abc");
        assert_eq!(
            table.insert_hashed(KEYS, range(b"abd"), 9, hash),
            Insert::New
        );
        assert_eq!(table.find_hashed(KEYS, range(b"abc"), hash), Some(7));
        assert_eq!(table.find_hashed(KEYS, range(b"abd"), hash), Some(9));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn duplicate_returns_the_first_representative() {
        let mut table = table_with_one();
        assert_eq!(table.insert(KEYS, range(b"abc"), 11), Insert::Duplicate(7));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn marker_checksum_is_the_low_sixteen_bits() {
        for key in [&b""[..], b"a", b"abc", b"2026-08-26T10:00:00Z INFO hc"] {
            let full = XxHash3_64::oneshot_with_seed(HASH_SEED, key);
            assert_eq!(marker_checksum(key), full as u16);
        }
    }

    #[test]
    fn growth_keeps_every_entry_findable() {
        let mut keys = Vec::new();
        let mut offsets = Vec::new();
        for i in 0..200usize {
            let key = format!("key-{i:04}");
            offsets.push(keys.len());
            keys.extend_from_slice(key.as_bytes());
        }
        let ranges = |i: usize| offsets[i]..offsets[i] + format!("key-{i:04}").len();
        let mut table = FingerprintTable::for_keys(0);
        assert_eq!(table.slots(), MIN_SLOTS);
        for i in 0..200 {
            assert_eq!(table.insert(&keys, ranges(i), i), Insert::New);
            for j in 0..=i {
                assert_eq!(table.find(&keys, ranges(j)), Some(j), "entry {j} after {i}");
            }
        }
        assert!(table.slots() > MIN_SLOTS);
        assert_eq!(table.len(), 200);
        assert!(!table.is_full());
    }
}
