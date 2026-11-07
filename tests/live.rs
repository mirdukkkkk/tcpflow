//! Live capture (SPEC.md 2, 3) on the loopback device of a new network namespace,
//! so no root is needed. Skipped where unprivileged user namespaces are not
//! available.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TCPFLOW: &str = env!("CARGO_BIN_EXE_tcpflow");

/// Brings `lo` up, starts tcpflow with the given arguments, waits until it listens,
/// runs one TCP exchange and one UDP datagram if asked, then sends SIGINT.
const SCRIPT: &str = r#"
import fcntl, signal, socket, struct, subprocess, sys, threading, time
tcpflow, cwd, traffic = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
args = sys.argv[4:]
s = socket.socket()
flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, struct.pack("16sH14x", b"lo", 0))[:18])[1]
fcntl.ioctl(s, 0x8914, struct.pack("16sH14x", b"lo", flags | 1))
p = subprocess.Popen([tcpflow] + args, cwd=cwd, stderr=subprocess.PIPE)
line = p.stderr.readline()
assert b"listening on lo" in line, line
if traffic:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 9999))
    srv.listen()
    def serve():
        c, _ = srv.accept()
        c.sendall(b"pong:" + c.recv(100))
        c.close()
    t = threading.Thread(target=serve)
    t.start()
    c = socket.create_connection(("127.0.0.1", 9999), source_address=("127.0.0.1", 40000))
    c.sendall(b"ping")
    assert c.recv(100) == b"pong:ping"
    c.close()
    t.join()
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9998))
time.sleep(0.3)
p.send_signal(signal.SIGINT)
try:
    sys.exit(p.wait(timeout=10))
except subprocess.TimeoutExpired:
    p.kill()
    sys.exit("tcpflow did not stop on SIGINT")
"#;

fn namespaces_available() -> bool {
    let ok = Command::new("unshare")
        .args(["-rn", "true"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipped: no unprivileged user and network namespaces");
    }
    ok
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tcpflow-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn capture(dir: &Path, traffic: bool, args: &[&str]) -> Output {
    Command::new("unshare")
        .args(["-rn", "python3", "-I", "-c", SCRIPT, TCPFLOW])
        .arg(dir)
        .arg(if traffic { "1" } else { "0" })
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn flows_and_unprocessed_packets() {
    if !namespaces_available() {
        return;
    }
    let dir = scratch("live");
    let out = capture(
        &dir,
        true,
        &[
            "-i",
            "lo",
            "-o",
            "out",
            "-w",
            "unk.pcap",
            "port 9999 or udp",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let read = |name: &str| std::fs::read(dir.join("out").join(name)).unwrap();
    assert_eq!(read("127.000.000.001.40000-127.000.000.001.09999"), b"ping");
    assert_eq!(
        read("127.000.000.001.09999-127.000.000.001.40000"),
        b"pong:ping"
    );
    assert!(
        String::from_utf8(read("report.xml"))
            .unwrap()
            .contains("<total_flows>2</total_flows>")
    );
    // the pcap header, then the UDP datagram: 16 bytes record header, 43 bytes frame
    assert_eq!(
        std::fs::read(dir.join("unk.pcap")).unwrap().len(),
        24 + 16 + 43
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn stops_on_sigint_without_traffic() {
    if !namespaces_available() {
        return;
    }
    let dir = scratch("live-idle");
    for args in [
        &["-i", "lo", "-o", "out"][..],
        &["-i", "lo", "-o", "out", "-K"],
    ] {
        let out = capture(&dir, false, args);
        assert!(out.status.success(), "{args:?}: {out:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
