//! `tcp_cmd`, `http_cmd`, `tcp_alert_fd` and `http_alert_fd` (SPEC.md 13.5).

use std::collections::VecDeque;
use std::process::Child;

use crate::log;
use crate::sys::command;
use crate::sys::fd::CallerFd;

/// At most this many commands of one kind run at a time.
const MAX_RUNNING: usize = 10;

/// A descriptor given by the caller for `open` and `close` lines.
struct Alert {
    name: &'static str,
    fd: Option<CallerFd>,
}

impl Alert {
    fn new(name: &'static str, fd: Option<i32>) -> Result<Alert, String> {
        let fd = match fd {
            None => None,
            Some(n) => Some(
                CallerFd::new(n).ok_or_else(|| format!("{name}={n}: not an open descriptor"))?,
            ),
        };
        Ok(Alert { name, fd })
    }

    fn line(&mut self, event: &str, path: &str) {
        if let Some(f) = self.fd.as_mut() {
            if let Err(e) = f.write_all(format!("{event}\t{path}\n").as_bytes()) {
                log::error(&format!("{}: {e}; no more alerts are written", self.name));
                self.fd = None;
            }
        }
    }
}

/// Commands run on closed files, with the path as their only argument.
struct Commands {
    cmd: Option<String>,
    running: VecDeque<Child>,
}

impl Commands {
    fn run(&mut self, path: &str) {
        let Some(cmd) = &self.cmd else {
            return;
        };
        self.running
            .retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_))));
        while self.running.len() >= MAX_RUNNING {
            if let Some(mut oldest) = self.running.pop_front() {
                let _ = oldest.wait();
            }
        }
        match command::with_argument(cmd, path) {
            Ok(child) => self.running.push_back(child),
            Err(e) => log::error(&format!("cannot run {cmd}: {e}")),
        }
    }

    fn wait_all(&mut self) {
        for mut c in self.running.drain(..) {
            let _ = c.wait();
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub tcp_cmd: Option<String>,
    pub http_cmd: Option<String>,
    pub tcp_alert_fd: Option<i32>,
    pub http_alert_fd: Option<i32>,
}

pub struct Hooks {
    tcp_alert: Alert,
    http_alert: Alert,
    tcp_cmd: Commands,
    http_cmd: Commands,
}

impl Hooks {
    pub fn new(opt: Options) -> Result<Hooks, String> {
        Ok(Hooks {
            tcp_alert: Alert::new("tcp_alert_fd", opt.tcp_alert_fd)?,
            http_alert: Alert::new("http_alert_fd", opt.http_alert_fd)?,
            tcp_cmd: Commands {
                cmd: opt.tcp_cmd,
                running: VecDeque::new(),
            },
            http_cmd: Commands {
                cmd: opt.http_cmd,
                running: VecDeque::new(),
            },
        })
    }

    /// No hooks, for tests and `-K`.
    pub fn none() -> Hooks {
        Hooks::new(Options {
            tcp_cmd: None,
            http_cmd: None,
            tcp_alert_fd: None,
            http_alert_fd: None,
        })
        .unwrap()
    }

    /// A flow file was created.
    pub fn flow_opened(&mut self, path: &str) {
        self.tcp_alert.line("open", path);
    }

    /// A flow file was closed and post-processed; `bodies` are its HTTP body files.
    pub fn flow_closed<'a>(&mut self, path: &str, bodies: impl Iterator<Item = &'a str>) {
        for body in bodies {
            self.http_alert.line("open", body);
            self.http_alert.line("close", body);
            self.http_cmd.run(body);
        }
        self.tcp_alert.line("close", path);
        self.tcp_cmd.run(path);
    }

    /// Wait for the commands that are still running.
    pub fn finish(&mut self) {
        self.http_cmd.wait_all();
        self.tcp_cmd.wait_all();
    }
}
