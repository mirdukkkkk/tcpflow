//! `-L` (SPEC.md 9.4).

use std::ffi::CString;
use std::process::{Command, Stdio};
use std::time::Duration;

const TCPFLOW: &str = env!("CARGO_BIN_EXE_tcpflow");
const PCAP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test1.pcap");

#[test]
fn console_output_waits_for_the_semaphore() {
    let name = format!("/tcpflow-test-{}", std::process::id());
    let c = CString::new(name.clone()).unwrap();
    // SAFETY: plain calls with a valid name; the semaphore is checked below.
    let sem = unsafe {
        libc::sem_open(
            c.as_ptr(),
            libc::O_CREAT,
            0o600 as libc::c_uint,
            0 as libc::c_uint,
        )
    };
    assert_ne!(sem, libc::SEM_FAILED);

    let out = std::env::temp_dir().join(format!("tcpflow-test-semlock-{}", std::process::id()));
    let mut child = Command::new(TCPFLOW)
        .args(["-c", "-L", &name, "-r", PCAP])
        .stdout(std::fs::File::create(&out).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let blocked = std::fs::metadata(&out).unwrap().len();
    // SAFETY: the semaphore is open.
    unsafe { libc::sem_post(sem) };
    assert!(child.wait().unwrap().success());
    let printed = std::fs::read(&out).unwrap();

    // SAFETY: as above.
    unsafe {
        libc::sem_close(sem);
        libc::sem_unlink(c.as_ptr());
    }
    std::fs::remove_file(&out).unwrap();
    assert_eq!(blocked, 0, "printed while the semaphore was taken");
    let plain = Command::new(TCPFLOW)
        .args(["-c", "-r", PCAP])
        .output()
        .unwrap();
    assert_eq!(printed, plain.stdout);
}

#[test]
fn a_semaphore_that_cannot_be_opened_is_an_error() {
    let name = format!("/{}", "x".repeat(300));
    let out = Command::new(TCPFLOW)
        .args(["-c", "-L", &name, "-r", PCAP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with(&format!("tcpflow: -L {name}: ")));
}
