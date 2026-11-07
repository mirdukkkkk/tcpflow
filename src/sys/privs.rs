//! Dropping root privileges (`-U`) and chroot (`-z`) (SPEC.md section 16).

use std::ffi::{CStr, CString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};

use crate::sys::files::Output;

/// Who to become.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    /// For `initgroups`; `None` clears the supplementary groups instead.
    pub user: Option<CString>,
}

/// A user or group name, looked up in the system databases.
struct Passwd {
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: CString,
}

fn lookup_user(name: &str) -> io::Result<Option<Passwd>> {
    let Ok(name) = CString::new(name) else {
        return Ok(None);
    };
    // SAFETY: valid pointers, and the buffer size passed is the buffer's.
    get_r(
        |e, b, r| unsafe {
            libc::getpwnam_r(name.as_ptr(), e.as_mut_ptr(), b.as_mut_ptr(), b.len(), r)
        },
        passwd,
    )
}

fn lookup_uid(uid: libc::uid_t) -> io::Result<Option<Passwd>> {
    // SAFETY: as above.
    get_r(
        |e, b, r| unsafe { libc::getpwuid_r(uid, e.as_mut_ptr(), b.as_mut_ptr(), b.len(), r) },
        passwd,
    )
}

fn lookup_group(name: &str) -> io::Result<Option<libc::gid_t>> {
    let Ok(name) = CString::new(name) else {
        return Ok(None);
    };
    // SAFETY: as above.
    get_r(
        |e, b, r| unsafe {
            libc::getgrnam_r(name.as_ptr(), e.as_mut_ptr(), b.as_mut_ptr(), b.len(), r)
        },
        |g: &libc::group| g.gr_gid,
    )
}

fn passwd(pw: &libc::passwd) -> Passwd {
    Passwd {
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        // SAFETY: get_r only hands over a filled-in entry; pw_name points into its buffer.
        name: unsafe { CStr::from_ptr(pw.pw_name) }.to_owned(),
    }
}

/// Call a `get*_r` function, growing the buffer while it is too small. `Ok(None)`
/// if there is no such entry.
fn get_r<E, T>(
    call: impl Fn(&mut MaybeUninit<E>, &mut [libc::c_char], &mut *mut E) -> libc::c_int,
    read: impl FnOnce(&E) -> T,
) -> io::Result<Option<T>> {
    let mut size = 1024;
    loop {
        let mut buf = vec![0 as libc::c_char; size];
        let mut entry = MaybeUninit::<E>::uninit();
        let mut res = std::ptr::null_mut();
        match call(&mut entry, &mut buf, &mut res) {
            0 if res.is_null() => return Ok(None),
            // SAFETY: on success the entry is filled in; its strings point into buf.
            0 => return Ok(Some(read(unsafe { entry.assume_init_ref() }))),
            libc::ERANGE if size < MAX_BUFFER => size *= 4,
            // some systems report a missing entry as an error
            libc::ENOENT | libc::ESRCH => return Ok(None),
            e => return Err(io::Error::from_raw_os_error(e)),
        }
    }
}

const MAX_BUFFER: usize = 1 << 20;

/// A decimal id. `u32::MAX` is `(uid_t)-1`, which means "unchanged" to setuid.
fn numeric_id(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|&id| id != u32::MAX)
}

/// Parse `user`, `uid`, `user:group`, `uid:gid` or `:group`. Each part is looked up
/// as a name first, then parsed as a number.
pub fn parse(spec: &str) -> Result<Target, String> {
    let err = |msg: &str| format!("-U {spec}: {msg}");
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    if user.is_empty() && group.is_none_or(str::is_empty) {
        return Err(err("empty user and group"));
    }
    let mut t = Target {
        // `:group` keeps the uid; setuid(getuid()) is what drops a setuid-root binary
        // SAFETY: getuid cannot fail.
        uid: unsafe { libc::getuid() },
        // always replaced below: by the user's group, the named group, or an error
        gid: 0,
        user: None,
    };
    let mut gid_known = user.is_empty();
    if !user.is_empty() {
        let lookup = |e: io::Error| err(&format!("cannot look up user '{user}': {e}"));
        let pw = match lookup_user(user).map_err(lookup)? {
            Some(pw) => Some(pw),
            None => {
                let uid = numeric_id(user).ok_or_else(|| err(&format!("unknown user '{user}'")))?;
                t.uid = uid;
                lookup_uid(uid).map_err(lookup)?
            }
        };
        if let Some(pw) = pw {
            t.uid = pw.uid;
            t.gid = pw.gid;
            t.user = Some(pw.name);
            gid_known = true;
        }
    }
    match group {
        Some(g) if !g.is_empty() => {
            t.gid = lookup_group(g)
                .map_err(|e| err(&format!("cannot look up group '{g}': {e}")))?
                .or_else(|| numeric_id(g))
                .ok_or_else(|| err(&format!("unknown group '{g}'")))?;
        }
        // a uid without a passwd entry would otherwise keep our group, usually root's
        _ if !gid_known => {
            return Err(err(
                "the uid has no passwd entry; give a group, as in uid:gid",
            ));
        }
        _ => {}
    }
    Ok(t)
}

/// Dropping privileges, once, after the first input is open.
pub struct Dropper {
    target: Target,
    chroot: Option<String>,
    /// Created outputs, handed to the new ids by descriptor, never by path.
    handover: Vec<OwnedFd>,
    done: bool,
}

impl Dropper {
    pub fn new(target: Target, chroot: Option<&str>) -> Result<Dropper, String> {
        let chroot = match chroot {
            None => None,
            Some(_) if target.uid == 0 => {
                return Err("-z requires -U with a non-root user".into());
            }
            Some(d) => Some(d.to_string()),
        };
        Ok(Dropper {
            target,
            chroot,
            handover: Vec::new(),
            done: false,
        })
    }

    /// Remember an output to hand over, if tcpflow created it.
    pub fn hand_over<T: AsFd>(&mut self, out: &Output<T>) -> Result<(), String> {
        if out.created {
            let fd = out.handle.as_fd().try_clone_to_owned();
            self.handover.push(fd.map_err(|e| e.to_string())?);
        }
        Ok(())
    }

    pub fn drop_now(&mut self) -> Result<(), String> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        let t = &self.target;
        let os = |what: &str| format!("{what}: {}", io::Error::last_os_error());
        for fd in self.handover.drain(..) {
            std::os::unix::fs::fchown(&fd, Some(t.uid), Some(t.gid))
                .map_err(|e| format!("cannot hand output to the new user: fchown: {e}"))?;
        }
        // groups before the chroot, so that they come from the real /etc/group, and
        // before setuid, which takes away the right to change them
        // SAFETY: valid arguments; failures are checked.
        let groups = match &t.user {
            Some(name) => unsafe { libc::initgroups(name.as_ptr(), t.gid as _) },
            None => unsafe { libc::setgroups(1, &t.gid) },
        };
        if groups != 0 {
            return Err(os("setting supplementary groups"));
        }
        if let Some(dir) = &self.chroot {
            std::os::unix::fs::chroot(dir).map_err(|e| format!("chroot {dir}: {e}"))?;
            std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
        }
        // SAFETY: plain system calls; failures are checked.
        if unsafe { libc::setgid(t.gid) } != 0 {
            return Err(os("setgid"));
        }
        if unsafe { libc::setuid(t.uid) } != 0 {
            return Err(os("setuid"));
        }
        if t.uid != 0 && (unsafe { libc::setuid(0) } == 0 || unsafe { libc::seteuid(0) } == 0) {
            return Err("still able to regain root after dropping privileges".into());
        }
        let user = t.user.as_ref().map(|u| u.to_string_lossy());
        crate::log::debug(
            1,
            &format!(
                "dropped privileges to uid={} gid={}{}",
                t.uid,
                t.gid,
                user.map_or(String::new(), |u| format!(" user={u}"))
            ),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups_grow_the_buffer() {
        let sizes = std::cell::RefCell::new(Vec::new());
        let r = get_r(
            |e: &mut MaybeUninit<u32>, b: &mut [libc::c_char], res: &mut *mut u32| {
                sizes.borrow_mut().push(b.len());
                if b.len() < 10000 {
                    return libc::ERANGE;
                }
                *res = e.write(7);
                0
            },
            |v| *v,
        );
        assert_eq!(r.unwrap(), Some(7));
        assert_eq!(*sizes.borrow(), [1024, 4096, 16384]);
        let too_big = get_r(|_: &mut MaybeUninit<u32>, _, _| libc::ERANGE, |v| *v);
        assert_eq!(too_big.unwrap_err().raw_os_error(), Some(libc::ERANGE));
    }

    #[test]
    fn numeric_ids() {
        assert_eq!(numeric_id("900"), Some(900));
        for bad in ["", "+5", "-5", "1x", "4294967295", "99999999999999999999"] {
            assert_eq!(numeric_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn specs() {
        let t = parse("900:990").unwrap();
        assert_eq!((t.uid, t.gid), (900, 990));
        let t = parse("0").unwrap();
        assert_eq!((t.uid, t.user.as_deref()), (0, Some(c"root")));
        let t = parse(":991").unwrap();
        assert_eq!(t.gid, 991);
        for bad in [
            "",
            ":",
            "1:-5",
            "tcpflow-no-such-user",
            ":tcpflow-no-such-group",
        ] {
            assert!(parse(bad).unwrap_err().starts_with("-U "), "{bad}");
        }
    }

    #[test]
    fn uid_without_passwd_entry_needs_a_group() {
        let uid = (60000..65000)
            .find(|&u| matches!(lookup_uid(u), Ok(None)))
            .unwrap();
        assert!(
            parse(&uid.to_string())
                .unwrap_err()
                .contains("give a group")
        );
        assert_eq!(parse(&format!("{uid}:5")).unwrap().gid, 5);
    }
}
