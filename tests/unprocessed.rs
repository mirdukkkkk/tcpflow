//! `-w` beyond the single-file conformance cases (SPEC.md 12).

use std::path::{Path, PathBuf};
use std::process::Command;

const UDP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/udp.pcap");
const HEADER: usize = 24;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run tcpflow in `dir` with `-w unk.pcap` and return the `-w` file.
fn unprocessed(dir: &Path, args: &[&str]) -> Vec<u8> {
    let status = Command::new(env!("CARGO_BIN_EXE_tcpflow"))
        .args(["-o", "out", "-w", "unk.pcap"])
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::read(dir.join("unk.pcap")).unwrap()
}

#[test]
fn several_inputs_share_one_header() {
    let dir = scratch("unk-several");
    let one = unprocessed(&dir, &["-r", UDP]);
    assert!(
        one.len() > HEADER,
        "udp.pcap has no TCP, so every packet is written"
    );
    let two = unprocessed(&dir, &["-r", UDP, "-r", UDP]);
    let mut expected = one.clone();
    expected.extend_from_slice(&one[HEADER..]);
    assert_eq!(two, expected);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn compressed_input_matches_the_plain_file() {
    let dir = scratch("unk-gz");
    let plain = unprocessed(&dir, &["-r", UDP]);
    let gz = dir.join("udp.pcap.gz");
    let mut enc = flate2::write::GzEncoder::new(
        std::fs::File::create(&gz).unwrap(),
        flate2::Compression::default(),
    );
    std::io::copy(&mut std::fs::File::open(UDP).unwrap(), &mut enc).unwrap();
    enc.finish().unwrap();
    assert_eq!(unprocessed(&dir, &["-r", gz.to_str().unwrap()]), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn split_mode_writes_the_same_packets() {
    let dir = scratch("unk-split");
    let plain = unprocessed(&dir, &["-r", UDP]);
    assert_eq!(unprocessed(&dir, &["-K", "-r", UDP]), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn requires_an_r_file() {
    let dir = scratch("unk-no-r");
    let out = Command::new(env!("CARGO_BIN_EXE_tcpflow"))
        .args(["-w", "unk.pcap", "-R", UDP])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("-w requires -r"));
    assert!(!dir.join("unk.pcap").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}
