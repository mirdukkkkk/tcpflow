//! Dropping root privileges (`-U`) and chroot (`-z`) (SPEC.md section 16).

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

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

fn lookup_user(name: &str) -> Option<Passwd> {
    by_user(|pw, buf, res| {
        let name = CString::new(name).ok()?;
        // SAFETY: all pointers are valid for the call; buf outlives the result.
        unsafe { libc::getpwnam_r(name.as_ptr(), pw, buf.as_mut_ptr(), buf.len(), res) };
        Some(())
    })
}

fn lookup_uid(uid: libc::uid_t) -> Option<Passwd> {
    by_user(|pw, buf, res| {
        // SAFETY: as above.
        unsafe { libc::getpwuid_r(uid, pw, buf.as_mut_ptr(), buf.len(), res) };
        Some(())
    })
}

fn by_user(
    call: impl Fn(*mut libc::passwd, &mut [libc::c_char], *mut *mut libc::passwd) -> Option<()>,
) -> Option<Passwd> {
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: passwd is plain data; zeroed is a valid initial value.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res = std::ptr::null_mut();
    call(&mut pw, &mut buf, &mut res)?;
    if res.is_null() {
        return None;
    }
    // SAFETY: on success pw_name points into buf, which is still alive.
    let name = unsafe { CStr::from_ptr(pw.pw_name) }.to_owned();
    Some(Passwd {
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        name,
    })
}

fn lookup_group(name: &str) -> Option<libc::gid_t> {
    let name = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: group is plain data; zeroed is a valid initial value.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call.
    unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut gr,
            buf.as_mut_ptr(),
            buf.len(),
            &mut res,
        )
    };
    (!res.is_null()).then_some(gr.gr_gid)
}

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
    // SAFETY: getuid and getgid cannot fail.
    let mut t = Target {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        user: None,
    };
    let mut gid_known = user.is_empty();
    if !user.is_empty() {
        let pw = match lookup_user(user) {
            Some(pw) => Some(pw),
            None => {
                let uid = numeric_id(user).ok_or_else(|| err(&format!("unknown user '{user}'")))?;
                t.uid = uid;
                lookup_uid(uid)
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

/// An output object and whether tcpflow created it. Only created objects are handed
/// to the new user, so a special file or an existing file is never given away.
pub struct Output<T> {
    pub handle: T,
    pub created: bool,
}

/// Open an output file for writing, creating it if it does not exist. An existing
/// file is truncated (a FIFO or device is just opened).
pub fn create_file(path: &str) -> io::Result<Output<File>> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => Ok(Output {
            handle: f,
            created: true,
        }),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let f = OpenOptions::new().write(true).truncate(true).open(path)?;
            Ok(Output {
                handle: f,
                created: false,
            })
        }
        Err(e) => Err(e),
    }
}

/// Make sure `path` is a directory, creating it (one level) if it is missing.
pub fn create_dir(path: &str) -> Result<Output<File>, String> {
    let created = match std::fs::create_dir(path) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(format!("cannot create {path}: {e}")),
    };
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | if created { libc::O_NOFOLLOW } else { 0 })
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ENOTDIR) => format!("outdir is not a directory: {path}"),
            _ => format!("{path}: {e}"),
        })?;
    Ok(Output {
        handle: dir,
        created,
    })
}

/// Dropping privileges, once, after the first input is open.
pub struct Dropper {
    target: Target,
    chroot: Option<CString>,
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
            Some(d) => Some(CString::new(d).map_err(|_| format!("-z {d}: invalid path"))?),
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
            // SAFETY: fd is an open descriptor we own.
            if unsafe { libc::fchown(fd.as_raw_fd(), t.uid, t.gid) } != 0 {
                return Err(os("cannot hand output to the new user: fchown"));
            }
        }
        if let Some(dir) = &self.chroot {
            // SAFETY: dir is a valid C string.
            if unsafe { libc::chroot(dir.as_ptr()) } != 0 {
                return Err(os(&format!("chroot {}", dir.to_string_lossy())));
            }
            // SAFETY: the literal is a valid C string.
            if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
                return Err(os("chdir /"));
            }
        }
        // groups first: setuid to non-root takes away the right to change them
        // SAFETY: valid arguments; failures are checked.
        let groups = match &t.user {
            Some(name) => unsafe { libc::initgroups(name.as_ptr(), t.gid as _) },
            None => unsafe { libc::setgroups(1, &t.gid) },
        };
        if groups != 0 {
            return Err(os("setting supplementary groups"));
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
        crate::demux::log::debug(
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
        let uid = (60000..65000).find(|&u| lookup_uid(u).is_none()).unwrap();
        assert!(
            parse(&uid.to_string())
                .unwrap_err()
                .contains("give a group")
        );
        assert_eq!(parse(&format!("{uid}:5")).unwrap().gid, 5);
    }

    #[test]
    fn existing_and_special_files_are_not_created() {
        assert!(!create_file("/dev/null").unwrap().created);
        let dir = std::env::temp_dir().join(format!("tcpflow-privs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap();
        assert!(create_dir(d).unwrap().created);
        assert!(!create_dir(d).unwrap().created);
        let f = format!("{d}/f");
        assert!(create_file(&f).unwrap().created);
        assert!(!create_file(&f).unwrap().created);
        std::os::unix::fs::symlink("/dev/null", format!("{d}/link")).unwrap();
        assert!(!create_file(&format!("{d}/link")).unwrap().created);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
