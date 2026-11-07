//! Everything that depends on the operating system: privileges, signals, files,
//! limits, semaphores, caller descriptors and commands. The rest of tcpflow calls
//! only these modules (and libpcap) for system services.

pub mod command;
pub mod fd;
pub mod files;
pub mod limits;
pub mod privs;
pub mod semlock;
pub mod signals;

/// The platform's `AF_INET` or `AF_INET6` value, for the report (SPEC.md 14).
pub fn address_family(addr: &std::net::IpAddr) -> i32 {
    match addr {
        std::net::IpAddr::V4(_) => libc::AF_INET,
        std::net::IpAddr::V6(_) => libc::AF_INET6,
    }
}
