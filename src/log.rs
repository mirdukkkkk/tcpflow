//! Messages on stderr, with the `-d` debug level.

use std::sync::atomic::{AtomicI32, Ordering};

static LEVEL: AtomicI32 = AtomicI32::new(1);

pub fn set_level(level: i32) {
    LEVEL.store(level, Ordering::Relaxed);
}

pub fn debug(level: i32, msg: &str) {
    if LEVEL.load(Ordering::Relaxed) >= level {
        eprintln!("tcpflow: {msg}");
    }
}

pub fn error(msg: &str) {
    eprintln!("tcpflow: {msg}");
}
