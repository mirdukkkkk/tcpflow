//! `-K` with a small open file limit (SPEC.md 11, D3).

use std::path::Path;
use std::process::Command;

fn run(dir: &Path, out: &str, extra: &[&str]) {
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/samplePcaps/jpegs.cap");
    let status = Command::new(env!("CARGO_BIN_EXE_tcpflow"))
        .args(["-K", "-o", out, "-r", pcap])
        .args(extra)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success());
}

fn pcaps(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "pcap"))
        .map(|p| {
            let data = std::fs::read(&p).unwrap();
            (p.file_name().unwrap().to_string_lossy().into_owned(), data)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn file_limit_does_not_change_the_output() {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-split-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    run(&dir, "unlimited", &[]);
    run(&dir, "limited", &["-f", "2"]);
    let expected = pcaps(&dir.join("unlimited"));
    assert!(expected.len() > 10, "jpegs.cap has many flows");
    assert_eq!(pcaps(&dir.join("limited")), expected);
    std::fs::remove_dir_all(&dir).unwrap();
}
