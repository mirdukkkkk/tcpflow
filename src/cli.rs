//! Command line options (SPEC.md section 2).

use crate::naming::{DEFAULT_TEMPLATE, apply_f_flags};

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
}

#[derive(Debug)]
pub struct Config {
    pub rfiles: Vec<String>,
    pub big_r_files: Vec<String>,
    pub expression: String,
    pub outdir: String,
    pub template: String,
    pub store_output: bool,
    pub md5: bool,
    pub max_bytes: Option<u64>,
    pub max_seek: u32,
    pub max_open: Option<usize>,
    pub report_path: Option<String>,
    pub enable_report: bool,
    pub console: Console,
    pub index: bool,
    pub quiet: bool,
    pub debug: i32,
    pub tdelta: i64,
    pub tcp_timeout: Option<i64>,
    pub command_line: String,
}

pub enum Action {
    Run(Box<Config>),
    Version,
    Help(u32),
}

const MAX_SEEK: u32 = 16 * 1024 * 1024;

/// Options that SPEC.md assigns to later phases.
const NOT_YET: &[char] = &[
    'a', 'e', 'x', 'E', 'Z', 'K', 'w', 'U', 'z', 'i', 'p', 'J', 'L',
];

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
        outdir: ".".into(),
        template: DEFAULT_TEMPLATE.into(),
        store_output: true,
        md5: false,
        max_bytes: None,
        max_seek: MAX_SEEK,
        max_open: None,
        report_path: None,
        enable_report: true,
        console: Console::default(),
        index: false,
        quiet: false,
        debug: 1,
        tdelta: 0,
        tcp_timeout: None,
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
            Short('o') => cfg.outdir = value(&mut p)?,
            Short('T') => {
                cfg.template = value(&mut p)?;
                if !cfg.template.contains("%c") {
                    cfg.template.push_str("%C%c");
                }
            }
            Short('F') => {
                let flags = value(&mut p)?;
                if flags.contains('X') {
                    cfg.store_output = false;
                }
                if flags.contains('M') {
                    cfg.md5 = true;
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
            Short('I') => cfg.index = true,
            Short('q') => cfg.quiet = true,
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
                    _ => eprintln!("tcpflow: -S: unknown parameter '{name}'"),
                }
            }
            Short(c) if NOT_YET.contains(&c) => {
                return Err(format!("-{c} is not implemented yet"));
            }
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
    // console output replaces non-printable bytes unless -B or -D (SPEC.md 9.1)
    cfg.console.strip_nonprint = !cfg.console.force_binary;
    Ok(Action::Run(Box::new(cfg)))
}

pub fn usage(level: u32) {
    println!("TCPFLOW version {VERSION}\n");
    println!("usage: tcpflow [-BcCDhIqsvV0g] [-b max_bytes] [-d debug_level] [-f max_fds]");
    println!("       [-F[ctTXMkmg]] [-l] [-m min_bytes] [-o outdir] [-r file] [-R file]");
    println!("       [-S name=value] [-T template] [-X xmlfile] [expression]");
    if level > 1 {
        println!("\nSee SPEC.md for every option and the filename template codes.");
    }
}
