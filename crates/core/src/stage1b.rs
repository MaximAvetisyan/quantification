use crate::config::MAX_RECORD_BYTES;
use crate::stage1::Unit;

const SEPARATOR: &[u8; 3] = br"},{";

fn record_eligible(len: usize) -> bool {
    len <= MAX_RECORD_BYTES
}

pub(crate) fn segment_line(line: &[u8], base: usize) -> Vec<Unit> {
    let end = base + line.len();
    let separators = separators(line, base);
    if separators.is_empty() {
        return vec![Unit {
            range: base..end,
            eligible: record_eligible(line.len()),
        }];
    }
    let mut units = Vec::with_capacity(separators.len() + 1);
    for k in 0..separators.len() {
        let start = if k == 0 { base } else { separators[k - 1] + 2 };
        let stop = separators[k] + 1;
        if let Some(len) = stop.checked_sub(start).filter(|len| *len > 0) {
            units.push(Unit {
                range: start..stop,
                eligible: record_eligible(len),
            });
        }
    }
    let start = separators[separators.len() - 1] + 2;
    if start < end {
        units.push(Unit {
            range: start..end,
            eligible: record_eligible(end - start),
        });
    }
    units
}

fn separators(line: &[u8], base: usize) -> Vec<usize> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + SEPARATOR.len() <= line.len() {
        if &line[at..at + SEPARATOR.len()] == SEPARATOR {
            found.push(base + at);
            at += SEPARATOR.len() - 1;
        } else {
            at += 1;
        }
    }
    found
}
