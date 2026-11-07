//! Graceful stop on SIGINT, SIGTERM and SIGHUP (SPEC.md D12).
//!
//! The first signal asks tcpflow to stop reading: open flows are then closed and
//! the report is written as usual. The handler is reset to the default action
//! (SA_RESETHAND), so a second signal ends the process immediately.

use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);
/// The live capture, woken by a stop: on Linux libpcap may wait for packets
/// without a timeout. The handle does nothing once the capture is closed.
static CAPTURE: OnceLock<pcap::BreakLoop> = OnceLock::new();

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
    // atomics only; a live capture has no other thread, so the handler never runs
    // while the capture is being closed
    if let Some(capture) = CAPTURE.get() {
        capture.breakloop();
    }
}

pub fn install() -> io::Result<()> {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: sigaction is all-zero when empty; the handler is async-signal-safe.
        // SA_RESETHAND makes a second signal end the process. No SA_RESTART, so a
        // read blocked on a pipe returns EINTR and the loop sees the stop request.
        let ok = unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESETHAND;
            libc::sigemptyset(&mut sa.sa_mask) == 0
                && libc::sigaction(sig, &sa, std::ptr::null_mut()) == 0
        };
        if !ok {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Has a stop been requested?
pub fn stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Let a stop wake `cap` while it waits for packets. One live capture per run.
pub fn wake_on_stop(cap: &mut pcap::Capture<pcap::Active>) {
    let _ = CAPTURE.set(cap.breakloop_handle());
}
