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

/// What an option's argument is, for the shell completions (`completions.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    File,
    Dir,
    Interface,
    User,
    /// `-S name=value`, from [`PARAMS`].
    Param,
    /// `-e`, `-x`, `-E`, from [`POST_PROCESSORS`].
    PostProcessor,
    /// `-F`, from [`F_FLAGS`].
    Flags,
    Number,
    Text,
}

/// One command line option. The order is the order of `tcpflow -h`.
pub struct Opt {
    pub letter: char,
    pub long: Option<&'static str>,
    /// The argument: its name in the help and what it is.
    pub value: Option<(&'static str, Value)>,
    pub repeatable: bool,
    /// One line for the completions.
    pub help: &'static str,
    /// The `-h` line: left column and text; `None` if another option's line covers it.
    pub line: Option<(&'static str, &'static str)>,
}

const fn opt(letter: char, help: &'static str) -> Opt {
    Opt {
        letter,
        long: None,
        value: None,
        repeatable: false,
        help,
        line: None,
    }
}

impl Opt {
    const fn value(mut self, name: &'static str, kind: Value) -> Opt {
        self.value = Some((name, kind));
        self
    }
    const fn long(mut self, name: &'static str) -> Opt {
        self.long = Some(name);
        self
    }
    const fn repeatable(mut self) -> Opt {
        self.repeatable = true;
        self
    }
    const fn line(mut self, left: &'static str, text: &'static str) -> Opt {
        self.line = Some((left, text));
        self
    }
}

/// Every option `parse` accepts (SPEC.md 2).
pub const OPTIONS: &[Opt] = &[
    opt('r', "read packets from a capture file")
        .value("file", Value::File)
        .repeatable()
        .line("-r file", "read packets from a capture file (repeatable; - is stdin; .gz .bz2 .xz .zip)"),
    opt('R', "read a file only to finish flows that are already open")
        .value("file", Value::File)
        .repeatable()
        .line("-R file", "read a file only to finish flows that are already open"),
    opt('l', "treat the remaining arguments as -r files")
        .line("-l", "treat the remaining arguments as -r files instead of a filter"),
    opt('i', "capture on a network interface")
        .value("iface", Value::Interface)
        .line("-i iface", "capture on a network interface (default: the first one)"),
    opt('p', "do not put the interface into promiscuous mode")
        .line("-p", "do not put the interface into promiscuous mode"),
    opt('o', "output directory")
        .value("outdir", Value::Dir)
        .line("-o outdir", "output directory (default .)"),
    opt('T', "flow file name template")
        .value("template", Value::Text)
        .line("-T template", "flow file name template (see -hh)"),
    opt('F', "name and output flags")
        .value("flags", Value::Flags)
        .repeatable()
        .line("-F flags", "name and output flags: c t T k m g, X (no flow files), M (MD5)"),
    opt('b', "store at most this many bytes per flow")
        .value("max_bytes", Value::Number)
        .line("-b max_bytes", "store at most this many bytes per flow"),
    opt('m', "a sequence gap larger than this starts a new flow")
        .value("bytes", Value::Number)
        .line("-m bytes", "a sequence gap larger than this starts a new flow (default 16777216)"),
    opt('f', "maximum number of open flow files")
        .value("max_fds", Value::Number)
        .line("-f max_fds", "maximum number of open flow files"),
    opt('X', "write the DFXML report to this file")
        .value("file", Value::File)
        .line("-X file", "write the DFXML report here (default outdir/report.xml)"),
    opt('c', "print flow data to stdout instead of files")
        .line("-c", "print flow data to stdout instead of files, no report"),
    opt('C', "like -c, without the flow name before each segment")
        .line("-C", "like -c, without the flow name before each segment"),
    opt('D', "print as hex dump").line("-D", "print as hex dump (implies -B)"),
    opt('B', "print bytes as they are")
        .line("-B", "print bytes as they are; -s replaces non-printable ones (default)"),
    opt('s', "replace non-printable bytes when printing (default)"),
    opt('0', "no newline after each printed segment")
        .line("-0", "no newline after each printed segment"),
    opt('g', "colour printed segments by direction")
        .line("-g", "colour printed segments by direction"),
    opt('J', "print segments as JSON lines")
        .line("-J", "print segments as JSON lines (implies -c unless -C)"),
    opt('L', "serialise printing across processes with a named semaphore")
        .value("name", Value::Text)
        .line("-L name", "serialise printing across processes with a named semaphore"),
    opt('I', "write a .findx packet index next to each flow file")
        .line("-I", "write a .findx packet index next to each flow file"),
    opt('K', "write one pcap file per flow instead of the data")
        .line("-K", "write one pcap file per flow instead of the data"),
    opt('w', "write packets that were not processed as TCP to a pcap file")
        .value("file", Value::File)
        .line("-w file", "write packets that were not processed as TCP to a pcap file"),
    opt('a', "post-process flows: HTTP bodies and MD5")
        .line("-a", "post-process flows: HTTP bodies and MD5"),
    opt('e', "enable a post-processor")
        .value("name", Value::PostProcessor)
        .repeatable()
        .line(
            "-e name",
            "enable a post-processor (http, md5); -x disables one;\n-E disables all, then enables one",
        ),
    opt('x', "disable a post-processor")
        .value("name", Value::PostProcessor)
        .repeatable(),
    opt('E', "disable all post-processors, then enable one").value("name", Value::PostProcessor),
    opt('Z', "do not decompress gzip or deflate HTTP bodies")
        .line("-Z", "do not decompress gzip or deflate HTTP bodies"),
    opt('S', "set a parameter")
        .value("name=val", Value::Param)
        .repeatable()
        .line("-S name=val", "set a parameter (see -hh)"),
    opt('U', "drop root privileges after opening the first input")
        .long("relinquish-privileges")
        .value("user", Value::User)
        .line("-U user", "drop root privileges after opening the first input"),
    opt('z', "chroot to this directory when dropping privileges")
        .long("chroot")
        .value("dir", Value::Dir)
        .line("-z dir", "chroot to dir when dropping privileges (needs -U)"),
    opt('q', "no warning about too many files").line("-q", "no warning about too many files"),
    opt('d', "debug level")
        .value("n", Value::Number)
        .line("-d n, -v", "debug level n; -v is -d 10"),
    opt('v', "debug level 10").long("verbose"),
    opt('V', "print the version")
        .long("version")
        .line("-V", "print the version; -h, -hh: this help"),
    opt('h', "print the help; twice for more").long("help").repeatable(),
];

/// One `-S` parameter (SPEC.md 13).
pub struct Param {
    pub name: &'static str,
    /// The value in the help, such as `N`.
    pub value: &'static str,
    pub help: &'static str,
}

pub const PARAMS: &[Param] = &[
    Param {
        name: "enable_report",
        value: "0",
        help: "no report",
    },
    Param {
        name: "tdelta",
        value: "N",
        help: "add N seconds to every timestamp",
    },
    Param {
        name: "tcp_timeout",
        value: "N",
        help: "close flows idle for more than N seconds",
    },
    Param {
        name: "tcp_cmd",
        value: "CMD",
        help: "run CMD with each closed flow file as argument",
    },
    Param {
        name: "http_cmd",
        value: "CMD",
        help: "run CMD with each HTTP body file as argument",
    },
    Param {
        name: "tcp_alert_fd",
        value: "N",
        help: "write open/close lines for flow files to descriptor N",
    },
    Param {
        name: "http_alert_fd",
        value: "N",
        help: "the same for HTTP body files",
    },
    Param {
        name: "http_max_body",
        value: "N",
        help: "largest HTTP body file, 0 for no limit (default 1 GiB)",
    },
    Param {
        name: "packet-buffer-timeout",
        value: "N",
        help: "libpcap read timeout in milliseconds (default 10)",
    },
];

/// The names `-e`, `-x` and `-E` take (SPEC.md 13.3).
pub const POST_PROCESSORS: &[(&str, &str)] = &[
    ("http", "HTTP bodies"),
    ("md5", "MD5 of every flow"),
    ("all", "every post-processor"),
];

/// The `-F` flags (SPEC.md 7.2).
pub const F_FLAGS: &[(char, &str)] = &[
    ('c', "always append the connection counter"),
    ('t', "prepend the Unix start time"),
    ('T', "prepend the ISO 8601 start time"),
    ('k', "directories by thousands of flows"),
    ('m', "directories by millions of flows"),
    ('g', "directories by billions of flows"),
    ('X', "store no flow files"),
    ('M', "add MD5 digests to the report"),
];

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
    s.push('\n');
    for o in OPTIONS {
        if let Some((left, text)) = o.line {
            let text = text.replace('\n', &format!("\n{:15}", ""));
            s.push_str(&format!("  {left:<12} {text}\n"));
        }
    }
    s.push_str("  expression   a libpcap filter, such as 'tcp port 80'\n");
    if level < 2 {
        return s;
    }
    s.push_str(
        "
parameters (-S name=value):
",
    );
    for p in PARAMS {
        s.push_str(&format!(
            "  {:<24} {}\n",
            format!("{}={}", p.name, p.value),
            p.help
        ));
    }
    s.push_str(
        "
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
