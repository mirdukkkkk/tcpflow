//! Process limits and resource usage.

/// The soft limit on open files, `None` if unlimited or unknown.
pub fn open_files() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes to the struct we pass.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0;
    #[allow(clippy::unnecessary_cast)] // rlim_t is not u64 on every platform
    (ok && limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur as u64)
}

/// User and system CPU seconds and the maximum resident set size, as the platform
/// reports it (KiB on Linux, bytes on macOS; SPEC.md 14).
pub fn usage() -> (f64, f64, i64) {
    // SAFETY: rusage is plain data, so all zeros is a valid value, and getrusage
    // only writes to the struct it is given.
    let ru = unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) != 0 {
            return (0.0, 0.0, 0);
        }
        ru
    };
    let secs = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
    (secs(ru.ru_utime), secs(ru.ru_stime), ru.ru_maxrss as i64)
}
