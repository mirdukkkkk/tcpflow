//! Writing classic pcap files, for `-K` and `-w` (SPEC.md sections 11 and 12).

use std::io::{self, Write};

/// One captured frame, as it is written back.
pub struct Record<'a> {
    /// The original timestamp, without `-S tdelta`.
    pub secs: u32,
    pub usecs: u32,
    pub len: u32,
    pub data: &'a [u8],
}

impl<'a> Record<'a> {
    pub fn new(header: &pcap::PacketHeader, data: &'a [u8]) -> Record<'a> {
        Record {
            secs: header.ts.tv_sec as u32,
            usecs: header.ts.tv_usec as u32,
            len: header.len,
            data,
        }
    }
}

/// The classic pcap file header, in this host's byte order.
pub fn write_header(out: &mut impl Write, linktype: u32, snaplen: u32) -> io::Result<()> {
    out.write_all(&0xa1b2c3d4u32.to_ne_bytes())?;
    out.write_all(&2u16.to_ne_bytes())?;
    out.write_all(&4u16.to_ne_bytes())?;
    out.write_all(&0u32.to_ne_bytes())?; // time zone
    out.write_all(&0u32.to_ne_bytes())?; // timestamp accuracy
    out.write_all(&snaplen.to_ne_bytes())?;
    out.write_all(&linktype.to_ne_bytes())
}

pub fn write_record(out: &mut impl Write, rec: &Record) -> io::Result<()> {
    for v in [rec.secs, rec.usecs, rec.data.len() as u32, rec.len] {
        out.write_all(&v.to_ne_bytes())?;
    }
    out.write_all(rec.data)
}

/// The `-w` file: every packet that is not processed (SPEC.md 12).
pub struct Unprocessed {
    path: String,
    out: pcap::Savefile,
}

impl Unprocessed {
    /// libpcap writes the header to `file` with the link type and snaplen of `first`,
    /// the first input. The link type is the canonical LINKTYPE value (D20).
    pub fn create(
        path: &str,
        file: std::fs::File,
        first: &pcap::Capture<pcap::Offline>,
    ) -> Result<Unprocessed, String> {
        use std::os::fd::IntoRawFd;
        // SAFETY: the descriptor is ours; libpcap takes ownership of it.
        let out = unsafe { first.savefile_raw_fd(file.into_raw_fd()) }
            .map_err(|e| format!("{path}: {e}"))?;
        Ok(Unprocessed {
            path: path.to_string(),
            out,
        })
    }

    pub fn write(&mut self, packet: &pcap::Packet) {
        self.out.write(packet);
    }

    pub fn finish(mut self) -> Result<(), String> {
        self.out.flush().map_err(|e| format!("{}: {e}", self.path))
    }
}
