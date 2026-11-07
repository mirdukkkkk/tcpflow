//! A file descriptor that the caller of tcpflow opened, such as `tcp_alert_fd`.

use std::fs::File;
use std::io::{self, Write};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;

/// Written to, never closed: it belongs to the caller, and two uses may share it.
pub struct CallerFd(ManuallyDrop<File>);

impl CallerFd {
    /// `None` if `n` is not an open descriptor.
    pub fn new(n: i32) -> Option<CallerFd> {
        // SAFETY: fcntl only queries the descriptor.
        if n < 0 || unsafe { libc::fcntl(n, libc::F_GETFD) } < 0 {
            return None;
        }
        // SAFETY: the descriptor is open, the caller keeps it open for the whole run,
        // and ManuallyDrop keeps tcpflow from closing it.
        Some(CallerFd(ManuallyDrop::new(unsafe { File::from_raw_fd(n) })))
    }

    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.0.write_all(data)
    }
}
