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
}

/// Write `data` at `offset`.
pub fn write_at(file: &mut File, offset: u64, data: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)
}

/// Move the whole content of `file` up by `by` bytes. The first `by` bytes keep their
/// old content (or become a hole); the caller overwrites them.
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
    Ok(())
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
    fn shift_keeps_old_prefix() {
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
        assert_eq!(out, b"ababcdef");
        std::fs::remove_file(&dir).unwrap();
    }
}
