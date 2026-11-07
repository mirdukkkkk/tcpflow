//! Building small captures and running tcpflow, for the integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const TCPFLOW: &str = env!("CARGO_BIN_EXE_tcpflow");

pub const SYN: u8 = 0x02;
pub const FIN: u8 = 0x01;
pub const ACK: u8 = 0x10;
pub const PSH: u8 = 0x08;

/// A fresh empty directory for one test.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(TCPFLOW)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

/// One TCP segment from 10.0.0.1:40000 to 10.0.0.2:80, or back with `reply`.
#[derive(Clone)]
pub struct Segment {
    pub reply: bool,
    pub seq: u32,
    pub flags: u8,
    pub data: Vec<u8>,
    /// TCP data offset in 32-bit words; 5 is a plain 20-byte header.
    pub data_offset: u8,
}

pub fn seg(seq: u32, flags: u8, data: &[u8]) -> Segment {
    Segment {
        reply: false,
        seq,
        flags,
        data: data.to_vec(),
        data_offset: 5,
    }
}

impl Segment {
    pub fn reply(mut self) -> Segment {
        self.reply = true;
        self
    }

    /// The IPv4 packet carrying this segment.
    pub fn ip(&self) -> Vec<u8> {
        let header = usize::from(self.data_offset.max(5)) * 4;
        let mut tcp = vec![0u8; header];
        let (sport, dport) = if self.reply {
            (80u16, 40000u16)
        } else {
            (40000, 80)
        };
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&self.seq.to_be_bytes());
        tcp[12] = self.data_offset << 4;
        tcp[13] = self.flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&self.data);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        let (src, dst) = if self.reply {
            ([10, 0, 0, 2], [10, 0, 0, 1])
        } else {
            ([10, 0, 0, 1], [10, 0, 0, 2])
        };
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        ip.extend_from_slice(&tcp);
        ip
    }
}

/// A classic pcap file of Ethernet frames, one second apart.
pub fn ethernet_pcap(path: &Path, segments: &[Segment]) {
    let frames: Vec<Vec<u8>> = segments
        .iter()
        .map(|s| {
            let mut f = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
            f.extend_from_slice(&s.ip());
            f
        })
        .collect();
    pcap(path, 1, &frames);
}

/// A classic pcap file with link type `linktype`.
pub fn pcap(path: &Path, linktype: u32, frames: &[Vec<u8>]) {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    for v in [0u32, 0, 65535, linktype] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for (i, f) in frames.iter().enumerate() {
        for v in [1_000_000 + i as u32, 0, f.len() as u32, f.len() as u32] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(f);
    }
    std::fs::write(path, out).unwrap();
}
