mod cli;
mod console;
mod decode;
mod demux;
mod naming;
mod report;
mod stream;

use std::io;
use std::process::ExitCode;

use cli::{Action, Config};
use decode::Decoded;
use demux::{Demux, Flow, FlowSink, PacketMeta, Timestamp, log};
use naming::Template;
use report::{Report, Summary};

/// Reports nowhere, for `-c` and `-S enable_report=0`.
struct NoReport;

impl FlowSink for NoReport {
    fn flow_closed(&mut self, _: &Flow) -> io::Result<()> {
        Ok(())
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse(args) {
        Ok(Action::Version) => {
            println!("TCPFLOW {}", cli::VERSION);
            ExitCode::SUCCESS
        }
        Ok(Action::Help(level)) => {
            cli::usage(level);
            ExitCode::SUCCESS
        }
        Ok(Action::Run(cfg)) => match run(&cfg) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("tcpflow: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("tcpflow: {e}");
            cli::usage(1);
            ExitCode::FAILURE
        }
    }
}

fn run(cfg: &Config) -> Result<ExitCode, String> {
    log::set_level(cfg.debug);
    if cfg.rfiles.is_empty() && cfg.big_r_files.is_empty() {
        return Err("live capture (-i) is not implemented yet; use -r".into());
    }
    let template = Template::parse(&cfg.template)?;
    if !template.uses_counter() {
        return Err(format!(
            "template '{}' has no connection counter",
            cfg.template
        ));
    }

    match std::fs::metadata(&cfg.outdir) {
        Ok(m) if !m.is_dir() => return Err(format!("outdir is not a directory: {}", cfg.outdir)),
        Ok(_) => {}
        Err(_) => std::fs::create_dir(&cfg.outdir)
            .map_err(|e| format!("cannot create {}: {e}", cfg.outdir))?,
    }

    let mut report = if cfg.enable_report {
        let path = cfg
            .report_path
            .clone()
            .unwrap_or_else(|| format!("{}/report.xml", cfg.outdir));
        Some(
            Report::create(&path, &cfg.command_line, cfg.tdelta)
                .map_err(|e| format!("{path}: {e}"))?,
        )
    } else {
        None
    };
    let mut no_report = NoReport;
    let sink: &mut dyn FlowSink = match report.as_mut() {
        Some(r) => r,
        None => &mut no_report,
    };

    let mut demux = Demux::new(
        demux::Options {
            outdir: cfg.outdir.clone(),
            template,
            store_output: cfg.store_output,
            max_bytes: cfg.max_bytes,
            max_seek: cfg.max_seek,
            max_open: cfg.max_open.unwrap_or_else(demux::default_max_open),
            tcp_timeout: cfg.tcp_timeout,
            index: cfg.index,
            console: cfg.console.enabled.then_some(console::Options {
                suppress_header: cfg.console.suppress_header,
                hex: cfg.console.hex,
                strip_nonprint: cfg.console.strip_nonprint,
                no_newline: cfg.console.no_newline,
                color: cfg.console.color,
            }),
        },
        sink,
    );

    let mut ok = true;
    demux.start_new_flows = true;
    for path in &cfg.rfiles {
        ok &= read_file(&mut demux, cfg, path)?;
    }
    demux.start_new_flows = false;
    for path in &cfg.big_r_files {
        ok &= read_file(&mut demux, cfg, path)?;
    }
    demux.close_all().map_err(|e| e.to_string())?;
    let summary = Summary {
        total_flows: demux.flows_created(),
        total_packets: demux.packets,
        max_open_flows: demux.max_open_files,
    };
    drop(demux);
    if let Some(r) = report {
        r.finish(&summary).map_err(|e| e.to_string())?;
    }
    warn_many_files(cfg, summary.total_flows);
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Process one capture file. Returns false if it could not be read to the end.
fn read_file(demux: &mut Demux, cfg: &Config, path: &str) -> Result<bool, String> {
    let mut cap = pcap::Capture::from_file(path).map_err(|e| format!("{path}: {e}"))?;
    let linktype = cap.get_datalink().0;
    if !decode::supported(linktype) {
        return Err(format!(
            "sorry - unknown datalink type {linktype} in {path}"
        ));
    }
    cap.filter(&cfg.expression, true)
        .map_err(|e| format!("{}: {e}", cfg.expression))?;
    loop {
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::NoMorePackets) => return Ok(true),
            Err(e) => {
                log::error(&format!("{path}: {e}"));
                return Ok(false);
            }
        };
        let meta = PacketMeta {
            ts: Timestamp {
                secs: packet.header.ts.tv_sec as i64 + cfg.tdelta,
                usecs: packet.header.ts.tv_usec as i64,
            },
            caplen: packet.header.caplen,
            len: packet.header.len,
        };
        match decode::decode(linktype, packet.data) {
            Decoded::Tcp(seg, link) => {
                demux
                    .process(&seg, link, &meta)
                    .map_err(|e| e.to_string())?;
            }
            Decoded::UnprocessedIp => {}
            Decoded::Other => continue,
        }
        demux.expire(meta.ts).map_err(|e| e.to_string())?;
    }
}

/// Suggest `-Fk` when a directory gets too many files (SPEC.md 2, `-q`).
fn warn_many_files(cfg: &Config, flows: u64) {
    if cfg.quiet || flows <= 10_000 {
        return;
    }
    let count = std::fs::read_dir(&cfg.outdir).map_or(0, |d| d.count());
    if count >= 10_000 {
        eprintln!(
            "*** tcpflow created {count} files in output directory {}",
            cfg.outdir
        );
        eprintln!("*** Next time, specify command-line options: -Fk , -Fm , or -Fg");
        eprintln!("*** This will automatically bin output into subdirectories.");
    }
}
