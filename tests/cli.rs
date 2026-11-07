use std::process::Command;

fn tcpflow(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tcpflow"))
        .args(args)
        .output()
        .expect("run tcpflow")
}

#[test]
fn version() {
    for flag in ["-V", "--version"] {
        let out = tcpflow(&[flag]);
        assert!(
            out.status.success(),
            "{flag} must exit with status 0 (SPEC D5)"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("TCPFLOW {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn invalid_option() {
    let out = tcpflow(&["--no-such-option"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn json_alone_implies_console_output() {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test1.pcap");
    let out = tcpflow(&["-J", "-o", dir.to_str().unwrap(), "-r", pcap]);
    assert!(out.status.success());
    assert_eq!(out.stdout, tcpflow(&["-c", "-J", "-r", pcap]).stdout);
    assert!(out.stdout.starts_with(b"{\"src_host\":\"192.168.1.102\""));
    let files = std::fs::read_dir(&dir).map_or(0, |d| d.count());
    assert_eq!(files, 0, "-J writes no flow files and no report (D21)");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn live_capture_does_not_mix_with_files() {
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test1.pcap");
    for args in [["-i", "lo", "-r", pcap], ["-i", "lo", "-R", pcap]] {
        let out = tcpflow(&args);
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).contains("-i cannot be used with -r or -R"));
    }
}

#[test]
fn unknown_device() {
    let out = tcpflow(&["-c", "-i", "tcpflow-no-such-device"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("tcpflow: tcpflow-no-such-device: "));
}
