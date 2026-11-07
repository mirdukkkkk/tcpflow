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
    assert!(out.stdout.is_empty(), "usage goes to stderr (SPEC.md 2)");
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: tcpflow"));
    let help = tcpflow(&["-h"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("-K "));
}

#[test]
fn json_alone_implies_console_output() {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let pcap = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/captures/http/two-connections.pcap"
    );
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
    let pcap = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/captures/http/two-connections.pcap"
    );
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

#[test]
fn unwritable_outdir_names_the_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("tcpflow-test-ro-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    // root (or CAP_DAC_OVERRIDE) writes anyway: then there is nothing to test
    if std::fs::File::create(dir.join("probe")).is_ok() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let pcap = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/captures/http/two-connections.pcap"
    );
    let out = tcpflow(&["-X", "/dev/null", "-o", dir.to_str().unwrap(), "-r", pcap]);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    let prefix = format!("tcpflow: cannot create {}/", dir.display());
    assert!(err.starts_with(&prefix), "{err}");
}

#[test]
fn links_in_the_output_directory_are_not_followed() {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("out")).unwrap();
    std::fs::write(dir.join("victim"), b"keep me").unwrap();
    std::os::unix::fs::symlink(dir.join("victim"), dir.join("out/report.xml")).unwrap();
    let pcap = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/captures/http/two-connections.pcap"
    );
    let out = tcpflow(&["-o", dir.join("out").to_str().unwrap(), "-r", pcap]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(std::fs::read(dir.join("victim")).unwrap(), b"keep me");
    // a report path the user names may be a link
    let named = dir.join("out/report.xml");
    let out = tcpflow(&[
        "-X",
        named.to_str().unwrap(),
        "-o",
        dir.join("out").to_str().unwrap(),
        "-r",
        pcap,
    ]);
    assert!(out.status.success());
    assert!(
        std::fs::read(dir.join("victim"))
            .unwrap()
            .starts_with(b"<?xml")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn console_output_creates_no_directory() {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-c-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let pcap = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/captures/http/two-connections.pcap"
    );
    assert!(
        tcpflow(&["-c", "-o", dir.to_str().unwrap(), "-r", pcap])
            .status
            .success()
    );
    assert!(!dir.exists());
}
