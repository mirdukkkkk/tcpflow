//! Running the user's commands.

use std::io;
use std::process::{Child, Command};

/// Start `cmd` in the shell with `arg` as its one argument. The argument is never
/// parsed by the shell (SPEC.md D7).
pub fn with_argument(cmd: &str, arg: &str) -> io::Result<Child> {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{cmd} \"$1\""))
        .arg("tcpflow")
        .arg(arg)
        .spawn()
}
