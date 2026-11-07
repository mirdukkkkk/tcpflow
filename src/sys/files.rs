//! Output files and directories (SPEC.md 16): created exclusively where possible,
//! and never through a symbolic link in the output directory (D36).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;

/// An output object and whether tcpflow created it. Only created objects are handed
/// to the new user, so a special file or an existing file is never given away.
pub struct Output<T> {
    pub handle: T,
    pub created: bool,
}

/// Options for a file in the output directory: a symbolic link there is never
/// followed, so nobody who can write to the directory can redirect tcpflow's writes.
pub fn output_file() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.custom_flags(libc::O_NOFOLLOW);
    o
}

/// Open an output file for writing, creating it if it does not exist. An existing
/// file is truncated (a FIFO or device is just opened). `follow` allows an existing
/// symbolic link, for a path the user named.
pub fn create_file(path: &str, follow: bool) -> io::Result<Output<File>> {
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
            let f = if follow {
                OpenOptions::new().write(true).truncate(true).open(path)?
            } else {
                output_file().write(true).truncate(true).open(path)?
            };
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

/// The process or the system has no file descriptors left (SPEC.md 8).
pub fn is_too_many_files(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_and_special_files_are_not_created() {
        assert!(!create_file("/dev/null", true).unwrap().created);
        let dir = std::env::temp_dir().join(format!("tcpflow-privs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap();
        assert!(create_dir(d).unwrap().created);
        assert!(!create_dir(d).unwrap().created);
        let f = format!("{d}/f");
        assert!(create_file(&f, false).unwrap().created);
        assert!(!create_file(&f, false).unwrap().created);
        std::os::unix::fs::symlink("/dev/null", format!("{d}/link")).unwrap();
        assert!(!create_file(&format!("{d}/link"), true).unwrap().created);
        assert!(create_file(&format!("{d}/link"), false).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
