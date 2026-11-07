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
