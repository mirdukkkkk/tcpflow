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
    // whether a skipped range takes disk space depends on the file system; ext4,
    // xfs and tmpfs keep it sparse
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    #[cfg(target_os = "linux")]
    assert!(
        meta.blocks() * 512 < 1 << 20,
        "the shift wrote {} bytes",
        meta.blocks() * 512
    );
    let report = report(&dir);
    assert!(report.contains("violations='1'"), "{report}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 10 segments of 60 bytes, then a FIN: longer than `-m 100`.
fn long_stream(dir: &std::path::Path) {
    let mut segs = vec![seg(999, SYN, b"")];
    for i in 0..10u32 {
        segs.push(seg(1000 + i * 60, ACK | PSH, &[b'a' + i as u8; 60]));
    }
    segs.push(seg(1600, ACK | FIN, b""));
    ethernet_pcap(&dir.join("in.pcap"), &segs);
}

#[test]
fn without_flow_files_the_stream_position_still_advances() {
    let dir = scratch("fx-long");
    long_stream(&dir);
    assert!(
        run(&dir, &["-FX", "-m", "100", "-o", "out", "-r", "in.pcap"])
            .status
            .success()
    );
    let report = report(&dir);
    assert_eq!(report.matches("<fileobject>").count(), 1, "{report}");
    assert!(report.contains("<filesize>600</filesize>"), "{report}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn console_output_keeps_one_flow_beyond_the_gap_limit() {
    let dir = scratch("c-long");
    long_stream(&dir);
    let out = run(&dir, &["-c", "-m", "100", "-T", "flow%N", "-r", "in.pcap"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        text.lines().filter(|l| l.starts_with("flow000: ")).count(),
        10,
        "{text}"
    );
    assert!(!text.contains("flow001"), "{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_retransmission_that_crosses_the_gap_limit_is_ignored() {
    let dir = scratch("gap-retrans");
    // with -m 3, the repeated "hello" is a gap: it closes the flow, and is then
    // recognised as a retransmission of the flow just closed (SPEC.md 5.2, 5.3)
    ethernet_pcap(
        &dir.join("in.pcap"),
        &[
            seg(999, SYN, b""),
            seg(1000, ACK, b"hello"),
            seg(1005, ACK, b"world"),
            seg(1000, ACK, b"hello"),
        ],
    );
    assert!(
        run(&dir, &["-m", "3", "-o", "out", "-r", "in.pcap"])
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(dir.join("out").join(FLOW)).unwrap(),
        b"helloworld"
    );
    assert!(!dir.join("out").join(format!("{FLOW}c1")).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn index_files_survive_running_out_of_descriptors() {
    let dir = scratch("index-emfile");
    let jpegs = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/captures/http/jpegs.pcap"
    );
    let run = |out: &str, limit: &str| {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "ulimit -n {limit}; exec \"$0\" -I -f 1000 -o {out} -r {jpegs}"
            ))
            .arg(TCPFLOW)
            .current_dir(&dir)
            .output()
            .unwrap()
    };
    assert!(run("plain", "1024").status.success());
    let out = run("few", "20");
    assert!(out.status.success(), "{out:?}");
    let list = |d: &str| {
        let mut v: Vec<_> = std::fs::read_dir(dir.join(d))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        v.sort();
        v
    };
    assert_eq!(list("few"), list("plain"));
    std::fs::remove_dir_all(&dir).unwrap();
}
