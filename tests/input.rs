//! Compressed inputs (SPEC.md section 3) and stopping on a signal (SPEC.md D12).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PCAP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/captures/http/two-connections.pcap"
);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tcpflow(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tcpflow"))
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

/// Every flow file in `dir`, with its content.
fn flows(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap() != "report.xml")
        .map(|p| {
            let data = std::fs::read(&p).unwrap();
            (p.file_name().unwrap().to_string_lossy().into_owned(), data)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn compressed_inputs_match_the_plain_file() {
    let dir = scratch("compressed");
    let raw = std::fs::read(PCAP).unwrap();

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&raw).unwrap();
    std::fs::write(dir.join("t.pcap.gz"), gz.finish().unwrap()).unwrap();

    let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    bz.write_all(&raw).unwrap();
    std::fs::write(dir.join("t.pcap.bz2"), bz.finish().unwrap()).unwrap();

    let mut xz = Vec::new();
    lzma_rs::xz_compress(&mut &raw[..], &mut xz).unwrap();
    std::fs::write(dir.join("t.pcap.xz"), xz).unwrap();

    let mut lzma = Vec::new();
    lzma_rs::lzma_compress(&mut &raw[..], &mut lzma).unwrap();
    std::fs::write(dir.join("t.pcap.lzma"), lzma).unwrap();

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("t.pcap", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&raw).unwrap();
    std::fs::write(dir.join("t.pcap.zip"), zip.finish().unwrap().into_inner()).unwrap();

    assert!(tcpflow(&["-o", "plain", "-r", PCAP], &dir).status.success());
    let expected = flows(&dir.join("plain"));
    assert_eq!(expected.len(), 4);
    for name in [
        "t.pcap.gz",
        "t.pcap.bz2",
        "t.pcap.xz",
        "t.pcap.lzma",
        "t.pcap.zip",
    ] {
        let out = format!("out-{name}");
        let result = tcpflow(&["-o", &out, "-r", name], &dir);
        assert!(result.status.success(), "{name}: {:?}", result);
        assert_eq!(flows(&dir.join(&out)), expected, "{name}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn corrupt_compressed_input_fails() {
    let dir = scratch("corrupt");
    std::fs::write(dir.join("bad.pcap.gz"), b"not gzip").unwrap();
    let out = tcpflow(&["-o", "out", "-r", "bad.pcap.gz"], &dir);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("decompression failed"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn compressed_input_that_is_not_a_capture_fails() {
    let dir = scratch("not-pcap");
    // more than a pipe buffer, so the decompressor is still writing when libpcap fails
    let mut enc = flate2::write::GzEncoder::new(
        std::fs::File::create(dir.join("junk.pcap.gz")).unwrap(),
        flate2::Compression::fast(),
    );
    let mut x: u32 = 1;
    for _ in 0..300_000 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        enc.write_all(&[(x >> 16) as u8]).unwrap();
    }
    enc.finish().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_tcpflow"))
        .args(["-o", "out", "-r", "junk.pcap.gz"])
        .current_dir(&dir)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            panic!("tcpflow hangs on a compressed input that is not a capture");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(1));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn sigterm_closes_flows_and_writes_the_report() {
    let dir = scratch("sigterm");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tcpflow"))
        .args(["-o", "out", "-r", "-"])
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // send every packet but keep stdin open, so tcpflow waits for more
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&std::fs::read(PCAP).unwrap()).unwrap();
    stdin.flush().unwrap();
    std::thread::sleep(Duration::from_millis(500));

    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "tcpflow did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(stdin);
    assert!(status.success(), "{status:?}");

    let report = std::fs::read_to_string(dir.join("out/report.xml")).unwrap();
    assert!(report.trim_end().ends_with("</dfxml>"));
    assert_eq!(report.matches("<fileobject>").count(), 4);
    assert_eq!(flows(&dir.join("out")).len(), 4);
    std::fs::remove_dir_all(&dir).unwrap();
}
