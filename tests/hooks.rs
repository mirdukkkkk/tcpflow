//! `tcp_cmd`, `http_cmd`, `tcp_alert_fd`, `http_alert_fd` (SPEC.md 13.5).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TCPFLOW: &str = env!("CARGO_BIN_EXE_tcpflow");
const JPEGS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/samplePcaps/jpegs.cap");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `tcpflow <args>` through sh in `dir`, so that `redirects` can open descriptors.
fn run(dir: &Path, args: &[&str], redirects: &str) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg(format!("exec \"$0\" \"$@\" {redirects}"))
        .arg(TCPFLOW)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn lines(path: PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

/// The flow files and HTTP body files in `out`.
fn outputs(out: &Path) -> (Vec<String>, Vec<String>) {
    let mut flows = Vec::new();
    let mut bodies = Vec::new();
    for e in std::fs::read_dir(out).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        let path = format!("out/{name}");
        if name.contains("HTTPBODY") {
            bodies.push(path);
        } else if name != "report.xml" {
            flows.push(path);
        }
    }
    flows.sort();
    bodies.sort();
    (flows, bodies)
}

/// Every file is opened once, then closed once.
fn check_alerts(alerts: &[String], files: &[String]) {
    for f in files {
        let open = alerts.iter().position(|l| *l == format!("open\t{f}"));
        let close = alerts.iter().position(|l| *l == format!("close\t{f}"));
        assert!(
            matches!((open, close), (Some(o), Some(c)) if o < c),
            "{f}: {alerts:?}"
        );
    }
    assert_eq!(alerts.len(), 2 * files.len(), "{alerts:?}");
}

#[test]
fn alerts_and_commands() {
    let dir = scratch("hooks");
    let out = run(
        &dir,
        &[
            "-a",
            "-o",
            "out",
            "-S",
            "tcp_alert_fd=3",
            "-S",
            "http_alert_fd=4",
            "-S",
            "tcp_cmd=echo >> tcp.list",
            "-S",
            "http_cmd=echo >> http.list",
            "-r",
            JPEGS,
        ],
        "3>tcp.alerts 4>http.alerts",
    );
    assert!(out.status.success(), "{out:?}");
    let (flows, bodies) = outputs(&dir.join("out"));
    assert_eq!((flows.len(), bodies.len()), (38, 14));
    check_alerts(&lines(dir.join("tcp.alerts")), &flows);
    check_alerts(&lines(dir.join("http.alerts")), &bodies);
    // the commands have finished when tcpflow exits
    let mut ran = lines(dir.join("tcp.list"));
    ran.sort();
    assert_eq!(ran, flows);
    let mut ran = lines(dir.join("http.list"));
    ran.sort();
    assert_eq!(ran, bodies);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn at_most_ten_commands_run_at_a_time() {
    let dir = scratch("hooks-limit");
    std::fs::create_dir(dir.join("running")).unwrap();
    let cmd =
        "tcp_cmd=touch running/$$; ls running | wc -l >> counts; sleep 0.05; rm running/$$; true";
    let out = run(&dir, &["-o", "out", "-S", cmd, "-r", JPEGS], "");
    assert!(out.status.success(), "{out:?}");
    let counts: Vec<usize> = lines(dir.join("counts"))
        .iter()
        .map(|l| l.trim().parse().unwrap())
        .collect();
    assert_eq!(counts.len(), 38);
    let max = counts.iter().max().unwrap();
    assert!((2..=10).contains(max), "{counts:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_path_is_not_parsed_by_the_shell() {
    let dir = scratch("hooks-quote");
    let outdir = "o'ut $(touch pwned)";
    let out = run(
        &dir,
        &[
            "-o",
            outdir,
            "-S",
            "tcp_cmd=printf '%s\\n' >> list",
            "-r",
            JPEGS,
        ],
        "",
    );
    assert!(out.status.success(), "{out:?}");
    assert!(!dir.join("pwned").exists());
    let ran = lines(dir.join("list"));
    assert_eq!(ran.len(), 38);
    assert!(
        ran.iter().all(|p| p.starts_with(&format!("{outdir}/"))),
        "{ran:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn alert_descriptor_must_be_open() {
    let dir = scratch("hooks-fd");
    let out = run(
        &dir,
        &["-o", "out", "-S", "tcp_alert_fd=9", "-r", JPEGS],
        "",
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("tcp_alert_fd=9: not an open descriptor"),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
