//! Graceful stop on SIGINT and SIGTERM (SPEC.md D12).
//!
//! The first signal asks tcpflow to stop reading: open flows are then closed and
//! the report is written as usual. The handler restores the default action, so a
//! second signal ends the process immediately.

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
    // SAFETY: sigaction is async-signal-safe; this restores the default action.
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(sig, &dfl, std::ptr::null_mut());
    }
}

pub fn install() {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only touches an atomic and calls sigaction. No
        // SA_RESTART, so a read blocked on a pipe returns EINTR and the reading
        // loop gets to see the stop request.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Has a stop been requested?
pub fn stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}
