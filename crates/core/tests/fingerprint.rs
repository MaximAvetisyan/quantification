use quantification_core::fingerprint::{
    FingerprintTable, HASH_SEED, Insert, KEY_BYTES_PER_UNIT, MAX_SLOTS, MIN_SLOTS, fingerprint,
    marker_checksum,
};
use quantification_core::stage1::split_span;
use quantification_core::wsnorm::normalize_into;

const GOLDEN: [(&[u8], u128, u16); 4] = [
    (b"", 0x99aa_06d3_0147_98d8_6001_c324_468d_497f, 0x94c2),
    (b"a", 0xa96f_af70_5af1_6834_e6c6_32b6_1e96_4e1f, 0x4e1f),
    (b"abc", 0x06b0_5ab6_733a_6185_78af_5f94_892f_3950, 0x3950),
    (
        b"2026-08-26T10:00:00Z INFO hc 10.0.0.1 ok",
        0x8c56_1550_fbf8_9c4e_530e_73d4_ebfb_5d8d,
        0x0751,
    ),
];

fn key_set(count: usize) -> (Vec<u8>, Vec<std::ops::Range<usize>>) {
    let mut keys = Vec::new();
    let mut ranges = Vec::new();
    for i in 0..count {
        let key = format!("unit-{i:08}");
        ranges.push(keys.len()..keys.len() + key.len());
        keys.extend_from_slice(key.as_bytes());
    }
    (keys, ranges)
}

#[test]
fn fixed_seed_golden_vectors() {
    assert_eq!(HASH_SEED, 0);
    for (bytes, hash, checksum) in GOLDEN {
        assert_eq!(fingerprint(bytes), hash, "bytes {bytes:?}");
        assert_eq!(marker_checksum(bytes), checksum, "bytes {bytes:?}");
        assert_eq!(fingerprint(bytes), fingerprint(bytes));
    }
}

#[test]
fn fingerprints_separate_distinct_inputs() {
    let (keys, ranges) = key_set(1000);
    let mut seen = std::collections::BTreeSet::new();
    for range in &ranges {
        assert!(seen.insert(fingerprint(&keys[range.clone()])));
    }
    assert_eq!(seen.len(), 1000);
    assert_ne!(fingerprint(b"a"), fingerprint(b"b"));
    assert_ne!(fingerprint(b"ab"), fingerprint(b"ba"));
    assert_ne!(marker_checksum(b"a"), marker_checksum(b"b"));
}

#[test]
fn pre_sized_from_key_bytes_and_clamped() {
    assert_eq!(FingerprintTable::for_keys(0).slots(), MIN_SLOTS);
    assert_eq!(FingerprintTable::for_keys(1).slots(), MIN_SLOTS);
    assert_eq!(
        FingerprintTable::for_keys(KEY_BYTES_PER_UNIT * MIN_SLOTS).slots(),
        MIN_SLOTS
    );
    assert_eq!(
        FingerprintTable::for_keys(KEY_BYTES_PER_UNIT * 257).slots(),
        512
    );
    assert_eq!(FingerprintTable::for_keys(1 << 20).slots(), 1 << 16);
    assert_eq!(FingerprintTable::for_keys(usize::MAX).slots(), MAX_SLOTS);
    for bytes in [0usize, 1, 1024, 1 << 20, usize::MAX] {
        let table = FingerprintTable::for_keys(bytes);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(!table.is_full());
    }
}

#[test]
fn hard_cap_degrades_to_full_without_growing_past_it() {
    let (keys, ranges) = key_set(MAX_SLOTS);
    let mut table = FingerprintTable::for_keys(keys.len());
    let mut inserted = 0usize;
    for (i, range) in ranges.iter().enumerate() {
        match table.insert(&keys, range.clone(), i) {
            Insert::New => inserted += 1,
            _ => panic!("distinct key {i} was not new"),
        }
        if table.is_full() {
            break;
        }
    }
    assert!(inserted > 0);
    assert!(table.is_full());
    assert_eq!(table.slots(), MAX_SLOTS);
    assert!(table.len() <= MAX_SLOTS * 3 / 4);
    let all_findable = |table: &FingerprintTable| {
        ranges
            .iter()
            .enumerate()
            .take(inserted)
            .all(|(i, range)| table.find(&keys, range.clone()) == Some(i))
    };
    assert!(all_findable(&table), "entry lost at the cap");
    for (i, range) in ranges.iter().enumerate().skip(inserted).take(8) {
        assert_eq!(table.insert(&keys, range.clone(), i), Insert::Full);
    }
    assert_eq!(table.slots(), MAX_SLOTS);
    assert_eq!(table.len(), inserted);
    assert!(all_findable(&table), "entry lost after saturation");
}

#[test]
fn lookups_do_not_depend_on_insertion_order() {
    let (keys, ranges) = key_set(500);
    let mut forward = FingerprintTable::for_keys(keys.len());
    for (i, range) in ranges.iter().enumerate() {
        assert_eq!(forward.insert(&keys, range.clone(), i), Insert::New);
    }
    let mut backward = FingerprintTable::for_keys(keys.len());
    for (i, range) in ranges.iter().enumerate().rev() {
        assert_eq!(backward.insert(&keys, range.clone(), i), Insert::New);
    }
    assert_eq!(forward.len(), backward.len());
    for (i, range) in ranges.iter().enumerate() {
        assert_eq!(forward.find(&keys, range.clone()), Some(i));
        assert_eq!(backward.find(&keys, range.clone()), Some(i));
    }
    assert!(!forward.is_full());
}

#[test]
fn raw_domain_groups_repeated_units_only() {
    let span = br"2026-08-26T10:00:00Z INFO hc 10.0.0.1 ok\n2026-08-26T10:00:00Z INFO hc 10.0.0.1 ok\n2026-08-26T10:00:01Z INFO hc 10.0.0.1 ok\n2026-08-26T10:00:00Z INFO hc 10.0.0.1 ok";
    let units = split_span(span);
    assert_eq!(units.len(), 4);
    let mut table = FingerprintTable::for_keys(span.len());
    let mut reps = Vec::new();
    for (i, unit) in units.iter().enumerate() {
        let range = unit.range.clone();
        reps.push(table.insert(span, range, i));
    }
    assert_eq!(
        reps,
        vec![
            Insert::New,
            Insert::Duplicate(0),
            Insert::New,
            Insert::Duplicate(0)
        ]
    );
    assert_eq!(table.len(), 2);
    assert_eq!(table.find(span, units[3].range.clone()), Some(0));
    assert_eq!(table.find(span, units[2].range.clone()), Some(2));
    assert_eq!(table.find(span, 0..0), None);
}

#[test]
fn ws_domain_groups_padded_duplicates() {
    let span = br"a\tb\na  b\na\t\tb\nc\td";
    let units = split_span(span);
    let mut arena = Vec::new();
    let mut ranges = Vec::new();
    for unit in &units {
        let mut scratch = Vec::new();
        normalize_into(&span[unit.range.clone()], &mut scratch);
        ranges.push(arena.len()..arena.len() + scratch.len());
        arena.extend_from_slice(&scratch);
    }
    let mut raw = FingerprintTable::for_keys(span.len());
    assert_eq!(raw.insert(span, units[0].range.clone(), 0), Insert::New);
    assert_eq!(raw.insert(span, units[1].range.clone(), 1), Insert::New);
    assert_eq!(raw.insert(span, units[2].range.clone(), 2), Insert::New);

    let mut ws = FingerprintTable::for_keys(arena.len());
    assert_eq!(ws.insert(&arena, ranges[0].clone(), 0), Insert::New);
    assert_eq!(
        ws.insert(&arena, ranges[1].clone(), 1),
        Insert::Duplicate(0)
    );
    assert_eq!(
        ws.insert(&arena, ranges[2].clone(), 2),
        Insert::Duplicate(0)
    );
    assert_eq!(ws.insert(&arena, ranges[3].clone(), 3), Insert::New);
    assert_eq!(&arena[ranges[0].clone()], b"a b");
    assert_eq!(ws.len(), 2);
    assert_eq!(ws.find(&arena, ranges[2].clone()), Some(0));
}

#[test]
fn empty_key_is_an_entry_like_any_other() {
    let keys = b"abcdef";
    let mut table = FingerprintTable::for_keys(keys.len());
    assert_eq!(table.insert(keys, 3..3, 5), Insert::New);
    assert_eq!(table.insert(keys, 3..3, 6), Insert::Duplicate(5));
    assert_eq!(table.insert(keys, 0..1, 7), Insert::New);
    assert_eq!(table.find(keys, 3..3), Some(5));
    assert_eq!(table.find(keys, 0..1), Some(7));
    assert_eq!(table.find(keys, 1..1), Some(5));
    assert_eq!(fingerprint(b""), fingerprint(b""));
}
