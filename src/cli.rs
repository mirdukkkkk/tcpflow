//! Command line options (SPEC.md section 2).

use crate::flow::naming::{DEFAULT_TEMPLATE, apply_f_flags, has_counter_code};
use crate::post;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default)]
pub struct Console {
    pub enabled: bool,
    pub suppress_header: bool,
    pub hex: bool,
    pub strip_nonprint: bool,
    pub force_binary: bool,
    pub no_newline: bool,
    pub color: bool,
    pub json: bool,
}

#[derive(Debug)]
pub struct Config {
    pub rfiles: Vec<String>,
    pub big_r_files: Vec<String>,
    pub expression: String,
    /// `-i`: live capture device; `None` is libpcap's first device.
    pub device: Option<String>,
    /// Off with `-p`.
    pub promisc: bool,
    /// `-S packet-buffer-timeout`, in milliseconds.
    pub buffer_timeout: i32,
    pub outdir: String,
    pub template: String,
    pub store_output: bool,
    pub post: post::Options,
    pub max_bytes: Option<u64>,
    pub max_seek: u32,
    pub max_open: Option<usize>,
    pub report_path: Option<String>,
    pub enable_report: bool,
    pub console: Console,
    pub index: bool,
    /// `-K`: one pcap file per flow (SPEC.md 11).
    pub split: bool,
    /// `-w`: where packets that are not processed go (SPEC.md 12).
    pub unprocessed: Option<String>,
    /// `-U`: drop privileges to this user/group (SPEC.md 16).
    pub relinquish: Option<String>,
    /// `-z`: chroot directory (SPEC.md 16).
    pub chroot: Option<String>,
    pub quiet: bool,
    pub debug: i32,
    pub tdelta: i64,
    pub tcp_timeout: Option<i64>,
    pub hooks: crate::output::hooks::Options,
    /// `-L`: semaphore name (SPEC.md 9.4).
    pub lock: Option<String>,
    pub command_line: String,
}

impl Config {
    /// Without input files, tcpflow captures live (SPEC.md 2).
    pub fn live(&self) -> bool {
        self.rfiles.is_empty() && self.big_r_files.is_empty()
    }
}

pub enum Action {
    Run(Box<Config>),
    Version,
    Help(u32),
}

const MAX_SEEK: u32 = 16 * 1024 * 1024;

/// Turn a post-processor on or off by name (`-e`, `-x`, `-E`).
fn set_post(post: &mut post::Options, name: &str, on: bool) -> Result<(), String> {
    match name {
        "md5" => post.md5 = on,
        "http" => post.http = on,
        "all" => {
            post.md5 = on;
            post.http = on;
        }
        // not carried over (SPEC.md 13.3); accepted so that old command lines work
        "netviz" | "tcpdemux" | "wifiviz" => {}
        other => return Err(format!("unknown post-processor '{other}'")),
    }
    Ok(())
}

fn value(p: &mut lexopt::Parser) -> Result<String, String> {
    p.value()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|_| "argument is not valid UTF-8".to_string())
}

fn number<T: std::str::FromStr>(opt: char, value: &str) -> Result<T, String> {
    value
        .trim()
        .parse()
        .map_err(|_| format!("-{opt}: invalid number '{value}'"))
}

pub fn parse(args: Vec<String>) -> Result<Action, String> {
    use lexopt::prelude::*;

    let command_line = args.join(" ");
    let mut cfg = Config {
        rfiles: Vec::new(),
        big_r_files: Vec::new(),
        expression: String::new(),
        device: None,
        promisc: true,
        buffer_timeout: 10,
        outdir: ".".into(),
        template: DEFAULT_TEMPLATE.into(),
        store_output: true,
        post: post::Options {
            decompress: true,
            max_body: 1 << 30,
            ..Default::default()
        },
        max_bytes: None,
        max_seek: MAX_SEEK,
        max_open: None,
        report_path: None,
        enable_report: true,
        console: Console::default(),
        index: false,
        split: false,
        unprocessed: None,
        relinquish: None,
        chroot: None,
        quiet: false,
        debug: 1,
        tdelta: 0,
        tcp_timeout: None,
        hooks: crate::output::hooks::Options {
            tcp_cmd: None,
            http_cmd: None,
            tcp_alert_fd: None,
            http_alert_fd: None,
        },
        lock: None,
        command_line,
    };
    let mut help = 0;
    let mut list_mode = false;
    let mut rest = Vec::new();

    let mut p = lexopt::Parser::from_args(args);
    let err = |e: lexopt::Error| e.to_string();
    while let Some(arg) = p.next().map_err(err)? {
        match arg {
            Short('V') | Long("version") => return Ok(Action::Version),
            Short('h') | Long("help") => help += 1,
            Short('v') | Long("verbose") => cfg.debug = 10,
            Short('d') => cfg.debug = number('d', &value(&mut p)?)?,
            Short('r') => cfg.rfiles.push(value(&mut p)?),
            Short('R') => cfg.big_r_files.push(value(&mut p)?),
            Short('l') => list_mode = true,
            Short('i') => cfg.device = Some(value(&mut p)?),
            Short('p') => cfg.promisc = false,
            Short('o') => cfg.outdir = value(&mut p)?,
            Short('T') => {
                cfg.template = value(&mut p)?;
                if !has_counter_code(&cfg.template) {
                    cfg.template.push_str("%C%c");
                }
            }
            Short('F') => {
                let flags = value(&mut p)?;
                if flags.contains('X') {
                    cfg.store_output = false;
                }
                if flags.contains('M') {
                    cfg.post.md5 = true; // SPEC.md D17
                }
                for c in apply_f_flags(&mut cfg.template, &flags) {
                    eprintln!("tcpflow: -F: invalid format specification '{c}'");
                }
            }
            Short('b') => {
                let n: i64 = number('b', &value(&mut p)?)?;
                cfg.max_bytes = u64::try_from(n).ok();
            }
            Short('m') => cfg.max_seek = number('m', &value(&mut p)?)?,
            Short('f') => cfg.max_open = Some(number('f', &value(&mut p)?)?),
            Short('X') => cfg.report_path = Some(value(&mut p)?),
            Short('c') => {
                cfg.console.enabled = true;
                cfg.enable_report = false;
            }
            Short('C') => {
                cfg.console.enabled = true;
                cfg.console.suppress_header = true;
            }
            Short('D') => {
                cfg.console.hex = true;
                cfg.console.force_binary = true;
            }
            Short('s') => {} // the default; kept for compatibility
            Short('B') => cfg.console.force_binary = true,
            Short('0') => cfg.console.no_newline = true,
            Short('g') => cfg.console.color = true,
            Short('J') => cfg.console.json = true,
            Short('I') => cfg.index = true,
            Short('K') => cfg.split = true,
            Short('w') => cfg.unprocessed = Some(value(&mut p)?),
            Short('U') | Long("relinquish-privileges") => cfg.relinquish = Some(value(&mut p)?),
            Short('z') | Long("chroot") => cfg.chroot = Some(value(&mut p)?),
            Short('q') => cfg.quiet = true,
            Short('L') => cfg.lock = Some(value(&mut p)?),
            Short('S') => {
                let v = value(&mut p)?;
                let Some((name, val)) = v.split_once('=') else {
                    return Err(format!("-S: invalid parameter '{v}'"));
                };
                match name {
                    "enable_report" => {
                        cfg.enable_report = !matches!(val, "0" | "no" | "NO" | "false")
                    }
                    "tdelta" => cfg.tdelta = number('S', val)?,
                    "tcp_timeout" => cfg.tcp_timeout = Some(number('S', val)?),
                    "packet-buffer-timeout" => cfg.buffer_timeout = number('S', val)?,
                    "http_max_body" => {
                        cfg.post.max_body = match number('S', val)? {
                            0 => u64::MAX,
                            n => n,
                        }
                    }
                    "tcp_cmd" => cfg.hooks.tcp_cmd = Some(val.to_string()),
                    "http_cmd" => cfg.hooks.http_cmd = Some(val.to_string()),
                    "tcp_alert_fd" => cfg.hooks.tcp_alert_fd = Some(number('S', val)?),
                    "http_alert_fd" => cfg.hooks.http_alert_fd = Some(number('S', val)?),
                    _ => eprintln!("tcpflow: -S: unknown parameter '{name}'"),
                }
            }
            Short('a') => set_post(&mut cfg.post, "all", true)?,
            Short('e') => set_post(&mut cfg.post, &value(&mut p)?, true)?,
            Short('x') => set_post(&mut cfg.post, &value(&mut p)?, false)?,
            Short('E') => {
                set_post(&mut cfg.post, "all", false)?;
                set_post(&mut cfg.post, &value(&mut p)?, true)?;
            }
            Short('Z') => cfg.post.decompress = false,
            Value(v) => rest.push(
                v.into_string()
                    .map_err(|_| "argument is not valid UTF-8".to_string())?,
            ),
            _ => return Err(arg.unexpected().to_string()),
        }
    }
    if help > 0 {
        return Ok(Action::Help(help));
    }
    if list_mode {
        cfg.rfiles.extend(rest);
    } else {
        cfg.expression = rest.join(" ");
    }
    // -J alone means -c (D21)
    if cfg.console.json && !cfg.console.enabled {
        cfg.console.enabled = true;
        cfg.enable_report = false;
    }
    // console output replaces non-printable bytes unless -B or -D (SPEC.md 9.1)
    cfg.console.strip_nonprint = !cfg.console.force_binary;
    Ok(Action::Run(Box::new(cfg)))
}

/// The help text: `-h` lists the options, `-hh` adds parameters and file name codes.
pub fn usage(level: u32) -> String {
    let mut s = format!(
        "TCPFLOW version {VERSION}

usage: tcpflow [-aBcCDgIJKpqsvVZ0] [-b max_bytes] [-d debug_level] [-e|-x|-E name]
               [-f max_fds] [-F[ctTXMkmg]] [-i iface] [-l] [-L semlock] [-m bytes]
               [-o outdir] [-r file] [-R file] [-S name=value] [-T template]
               [-U user[:group]] [-w file] [-X xmlfile] [-z chroot_dir] [expression]
"
    );
    if level < 1 {
        return s;
    }
    s.push_str(
        "
  -r file      read packets from a capture file (repeatable; - is stdin; .gz .bz2 .xz .zip)
  -R file      read a file only to finish flows that are already open
  -l           treat the remaining arguments as -r files instead of a filter
  -i iface     capture on a network interface (default: the first one)
  -p           do not put the interface into promiscuous mode
  -o outdir    output directory (default .)
  -T template  flow file name template (see -hh)
  -F flags     name and output flags: c t T k m g, X (no flow files), M (MD5)
  -b max_bytes store at most this many bytes per flow
  -m bytes     a sequence gap larger than this starts a new flow (default 16777216)
  -f max_fds   maximum number of open flow files
  -X file      write the DFXML report here (default outdir/report.xml)
  -c           print flow data to stdout instead of files, no report
  -C           like -c, without the flow name before each segment
  -D           print as hex dump (implies -B)
  -B           print bytes as they are; -s replaces non-printable ones (default)
  -0           no newline after each printed segment
  -g           colour printed segments by direction
  -J           print segments as JSON lines (implies -c unless -C)
  -L name      serialise printing across processes with a named semaphore
  -I           write a .findx packet index next to each flow file
  -K           write one pcap file per flow instead of the data
  -w file      write packets that were not processed as TCP to a pcap file
  -a           post-process flows: HTTP bodies and MD5
  -e name      enable a post-processor (http, md5); -x disables one;
               -E disables all, then enables one
  -Z           do not decompress gzip or deflate HTTP bodies
  -S name=val  set a parameter (see -hh)
  -U user      drop root privileges after opening the first input
  -z dir       chroot to dir when dropping privileges (needs -U)
  -q           no warning about too many files
  -d n, -v     debug level n; -v is -d 10
  -V           print the version; -h, -hh: this help
  expression   a libpcap filter, such as 'tcp port 80'
",
    );
    if level < 2 {
        return s;
    }
    s.push_str(
        "
parameters (-S name=value):
  enable_report=0          no report
  tdelta=N                 add N seconds to every timestamp
  tcp_timeout=N            close flows idle for more than N seconds
  tcp_cmd=CMD              run CMD with each closed flow file as argument
  http_cmd=CMD             run CMD with each HTTP body file as argument
  tcp_alert_fd=N           write open/close lines for flow files to descriptor N
  http_alert_fd=N          the same for HTTP body files
  http_max_body=N          largest HTTP body file, 0 for no limit (default 1 GiB)
  packet-buffer-timeout=N  libpcap read timeout in milliseconds (default 10)

file name template codes (-T), default %A.%a-%B.%b%V%v%C%c:
  %A %a        source address, source port (5 digits)
  %B %b        destination address, destination port
  %E %e        source, destination MAC address (zeros if not Ethernet)
  %V %v        '--' and the VLAN ID, if the flow has one
  %T %t        flow start, ISO 8601 UTC and Unix seconds
  %c %C %#     connection counter if > 0, 'c' if > 0, counter always
  %N %K %M %G  flow number in groups of 3 digits: units, thousands,
               millions, billions (for directory trees, -Fk -Fm -Fg)
  %S           session ID, 20 digits
  %%           a literal %
  '/' in the expanded name creates directories
",
    );
    s
}
