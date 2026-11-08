//! A flow file as a byte array indexed by stream offset (SPEC.md section 6).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// The set of stream offsets that have been seen, as disjoint half-open ranges.
#[derive(Debug, Default)]
pub struct Seen {
    ranges: BTreeMap<u64, u64>, // start -> end
    total: u64,
}

impl Seen {
    pub fn add(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let (mut start, mut end) = (start, start + len);
        // merge with every range that overlaps or touches [start, end)
        let first = self
            .ranges
            .range(..=start)
            .next_back()
            .filter(|(_, e)| **e >= start)
            .map(|(s, _)| *s)
            .unwrap_or(start);
        let touching: Vec<(u64, u64)> = self
            .ranges
            .range(first..=end)
            .map(|(s, e)| (*s, *e))
            .collect();
        for (s, e) in touching {
            self.ranges.remove(&s);
            self.total -= e - s;
            start = start.min(s);
            end = end.max(e);
        }
        self.ranges.insert(start, end);
        self.total += end - start;
    }

    /// Number of distinct bytes seen.
    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Every offset moves up by `by` (SPEC.md 6.2).
    pub fn shift(&mut self, by: u64) {
        self.ranges = std::mem::take(&mut self.ranges)
            .into_iter()
            .map(|(s, e)| (s + by, e + by))
            .collect();
    }
}

/// Write `data` at `offset`.
pub fn write_at(file: &mut File, offset: u64, data: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)
}

/// Move the whole content of `file` up by `by` bytes; the first `by` bytes become
/// zeros, as any part of the stream that has not been seen (SPEC.md 6.1, 6.2).
pub fn shift_up(file: &mut File, by: u64) -> io::Result<()> {
    const CHUNK: u64 = 64 * 1024;
    let size = file.metadata()?.len();
    let mut buf = vec![0u8; CHUNK as usize];
    let mut end = size;
    while end > 0 {
        let n = end.min(CHUNK);
        let start = end - n;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buf[..n as usize])?;
        write_at(file, start + by, &buf[..n as usize])?;
        end = start;
    }
    buf.fill(0);
    let mut at = 0;
    while at < by.min(size) {
        let n = (by.min(size) - at).min(CHUNK);
        write_at(file, at, &buf[..n as usize])?;
        at += n;
    }
    Ok(())
}

/// Index lines are `offset|seconds.microseconds|length` (SPEC.md 10).
fn read_index(path: &str) -> io::Result<Vec<(u64, String)>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let (offset, rest) = line.split_once('|')?;
            Some((offset.parse().ok()?, rest.to_string()))
        })
        .collect())
}

fn write_index(path: &str, lines: &[(u64, String)]) -> io::Result<()> {
    let mut out = String::new();
    for (offset, rest) in lines {
        out.push_str(&format!("{offset}|{rest}\n"));
    }
    std::fs::write(path, out)
}

/// Add `by` to every offset: the data moved up (SPEC.md 6.2).
pub fn shift_index(path: &str, by: u64) -> io::Result<()> {
    let mut lines = read_index(path)?;
    for (offset, _) in &mut lines {
        *offset += by;
    }
    write_index(path, &lines)
}

/// Sort by offset, keeping arrival order for equal offsets.
pub fn sort_index(path: &str) -> io::Result<()> {
    let mut lines = read_index(path)?;
    lines.sort_by_key(|(offset, _)| *offset);
    write_index(path, &lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_merges_ranges() {
        let mut s = Seen::default();
        s.add(0, 10);
        s.add(20, 5);
        assert_eq!(s.len(), 15);
        s.add(5, 10); // overlaps [0,10), touches nothing else
        assert_eq!(s.len(), 20);
        s.add(15, 5); // bridges [0,15) and [20,25)
        assert_eq!(s.len(), 25);
        s.add(0, 25);
        assert_eq!(s.len(), 25);
        assert_eq!(s.ranges.len(), 1);
    }

    #[test]
    fn shift_leaves_zeros_before_the_old_content() {
        let dir = std::env::temp_dir().join(format!("tcpflow-shift-{}", std::process::id()));
        let mut f = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dir)
            .unwrap();
        f.write_all(b"abcdef").unwrap();
        shift_up(&mut f, 2).unwrap();
        let mut out = Vec::new();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"\0\0abcdef");
        std::fs::remove_file(&dir).unwrap();
    }
}
