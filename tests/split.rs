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

#[test]
fn split_files_survive_running_out_of_descriptors() {
    let dir =
        std::env::temp_dir().join(format!("tcpflow-test-split-emfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let jpegs = concat!(env!("CARGO_MANIFEST_DIR"), "/samplePcaps/jpegs.cap");
    let count = |out: &str| -> usize {
        std::fs::read_dir(dir.join(out))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "pcap"))
            .map(|p| {
                let d = std::fs::read(&p).unwrap();
                let (mut at, mut n) = (24, 0);
                while at < d.len() {
                    at += 16 + u32::from_le_bytes(d[at + 8..at + 12].try_into().unwrap()) as usize;
                    n += 1;
                }
                n
            })
            .sum()
    };
    let run = |out: &str, limit: &str| {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "ulimit -n {limit}; exec \"$0\" -K -f 1000 -o {out} -r {jpegs}"
            ))
            .arg(env!("CARGO_BIN_EXE_tcpflow"))
            .current_dir(&dir)
            .status()
            .unwrap()
    };
    assert!(run("plain", "1024").success());
    assert!(run("few", "20").success());
    assert_eq!(count("few"), count("plain"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn flows_with_the_same_file_name_share_the_file() {
    let dir =
        std::env::temp_dir().join(format!("tcpflow-test-split-shared-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test1.pcap");
    let packets = |out: &str| -> usize {
        std::fs::read_dir(dir.join(out))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "pcap"))
            .map(|p| {
                let d = std::fs::read(&p).unwrap();
                let (mut at, mut n) = (24, 0);
                while at < d.len() {
                    at += 16 + u32::from_le_bytes(d[at + 8..at + 12].try_into().unwrap()) as usize;
                    n += 1;
                }
                n
            })
            .sum()
    };
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_tcpflow"))
            .args(args)
            .current_dir(&dir)
            .status()
            .unwrap()
    };
    assert!(run(&["-K", "-o", "plain", "-r", pcap]).success());
    // %A alone: every flow from one address goes to the same file
    assert!(run(&["-K", "-T", "%A", "-o", "shared", "-r", pcap]).success());
    assert_eq!(packets("shared"), packets("plain"));
    std::fs::remove_dir_all(&dir).unwrap();
}
