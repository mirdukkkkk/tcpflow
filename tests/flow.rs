//! Stream reconstruction on crafted captures (SPEC.md 5, 6).

mod common;

use common::*;

const FLOW: &str = "010.000.000.001.40000-010.000.000.002.00080";

fn report(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("out/report.xml")).unwrap()
}

#[test]
fn data_before_the_guessed_start_is_shifted_in_with_zeros() {
    let dir = scratch("shift");
    // no SYN: the first segment sets the start; "XX" belongs 4 bytes earlier
    ethernet_pcap(
        &dir.join("in.pcap"),
        &[
            seg(1000, ACK, b"abcdef"),
            seg(996, ACK, b"XX"),
            seg(1006, ACK | FIN, b""),
        ],
    );
    assert!(run(&dir, &["-o", "out", "-r", "in.pcap"]).status.success());
    assert_eq!(
        std::fs::read(dir.join("out").join(FLOW)).unwrap(),
        b"XX\0\0abcdef"
    );
    let report = report(&dir);
    // the FIN closed the flow, and its size includes the shift
    assert!(report.contains("<filesize>10</filesize>"), "{report}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shifting_is_limited_and_keeps_the_file_sparse() {
    let dir = scratch("shift-limit");
    // each segment 15 MB before the previous one: the first shift fits in -m, the
    // second would exceed it, and the next segment is a gap that starts a new flow
    let mut segs = vec![seg(2_000_000_000, ACK, b"a")];
    for i in 1..4u32 {
        segs.push(seg(2_000_000_000 - i * 15_000_000, ACK, b"b"));
    }
    ethernet_pcap(&dir.join("in.pcap"), &segs);
    assert!(run(&dir, &["-o", "out", "-r", "in.pcap"]).status.success());
    let meta = std::fs::metadata(dir.join("out").join(FLOW)).unwrap();
    assert_eq!(meta.len(), 15_000_001);
    use std::os::unix::fs::MetadataExt;
    assert!(
        meta.blocks() * 512 < 1 << 20,
        "the shift wrote {} bytes",
        meta.blocks() * 512
    );
    let report = report(&dir);
    assert!(report.contains("violations='1'"), "{report}");
    std::fs::remove_dir_all(&dir).unwrap();
}
