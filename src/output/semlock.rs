//! `-L`: console output serialised across processes by a named semaphore (SPEC.md 9.4).

use std::ffi::CString;
use std::io;

pub struct SemLock {
    sem: *mut libc::sem_t,
}

/// Held while one segment is printed.
pub struct Held<'a>(&'a SemLock);

impl SemLock {
    /// Open the semaphore `name`, creating it with the value 1 if it does not exist.
    pub fn open(name: &str) -> Result<SemLock, String> {
        let c = CString::new(name).map_err(|_| format!("-L {name}: invalid name"))?;
        // SAFETY: a valid C string; mode and value are passed as C unsigned ints.
        let sem = unsafe {
            libc::sem_open(
                c.as_ptr(),
                libc::O_CREAT,
                0o666 as libc::c_uint,
                1 as libc::c_uint,
            )
        };
        if sem == libc::SEM_FAILED {
            return Err(format!("-L {name}: {}", io::Error::last_os_error()));
        }
        Ok(SemLock { sem })
    }

    pub fn hold(&self) -> io::Result<Held<'_>> {
        // SAFETY: sem is open until drop.
        while unsafe { libc::sem_wait(self.sem) } != 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        Ok(Held(self))
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        // SAFETY: we hold the semaphore.
        unsafe { libc::sem_post(self.0.sem) };
    }
}

impl Drop for SemLock {
    fn drop(&mut self) {
        // SAFETY: sem is open and no longer used.
        unsafe { libc::sem_close(self.sem) };
    }
}
