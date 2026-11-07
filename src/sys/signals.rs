//! Graceful stop on SIGINT, SIGTERM and SIGHUP (SPEC.md D12).
//!
//! The first signal asks tcpflow to stop reading: open flows are then closed and
//! the report is written as usual. The handler is reset to the default action
//! (SA_RESETHAND), so a second signal ends the process immediately.

use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);
/// The live capture, woken by a stop: on Linux libpcap may wait for packets
/// without a timeout.
static CAPTURE: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "C" {
    fn pcap_breakloop(p: *mut libc::c_void);
}

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
    let cap = CAPTURE.load(Ordering::SeqCst);
    if !cap.is_null() {
        // SAFETY: the capture is alive while it is registered (Wake), the handler
        // runs on the thread that owns it, and pcap_breakloop may be called from a
        // signal handler.
        unsafe { pcap_breakloop(cap) };
    }
}

pub fn install() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only touches atomics and calls pcap_breakloop.
        // SA_RESETHAND makes a second signal end the process. No SA_RESTART, so a
        // read blocked on a pipe returns EINTR and the loop sees the stop request.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = libc::SA_RESETHAND;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Has a stop been requested?
pub fn stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// A live capture that a stop wakes. Owning it guarantees that the handler forgets
/// the capture before it is closed: `drop` runs before the field is dropped.
pub struct Wake(pcap::Capture<pcap::Active>);

pub fn wake_on_stop(cap: pcap::Capture<pcap::Active>) -> Wake {
    CAPTURE.store(cap.as_ptr().cast(), Ordering::SeqCst);
    Wake(cap)
}

impl Wake {
    pub fn capture(&mut self) -> &mut pcap::Capture<pcap::Active> {
        &mut self.0
    }
}

impl Drop for Wake {
    fn drop(&mut self) {
        CAPTURE.store(std::ptr::null_mut(), Ordering::SeqCst);
    }
}
