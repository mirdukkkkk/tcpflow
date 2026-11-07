mod cli;
mod console;
mod decode;
mod demux;
mod http;
mod input;
mod mime;
mod naming;
mod pcapfile;
mod post;
mod privs;
mod report;
mod signals;
mod split;
mod stream;
mod wifi;

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
    fn flow_closed(&mut self, _: &Flow, _: &post::Results) -> io::Result<()> {
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
    if cfg.device.is_some() && !cfg.live() {
        return Err("-i cannot be used with -r or -R".into());
    }
    if cfg.unprocessed.is_some() && cfg.rfiles.is_empty() && !cfg.live() {
        return Err("-w requires -r or live capture".into());
    }
    if cfg.post.any() && !cfg.store_output {
        return Err("post-processing requires storing output (it cannot be used with -FX)".into());
    }
    let template = Template::parse(&cfg.template)?;
    if !template.uses_counter() {
        return Err(format!(
            "template '{}' has no connection counter",
            cfg.template
        ));
    }

    let mut late = Late {
        unprocessed: None,
        dropper: match (&cfg.relinquish, &cfg.chroot) {
            (Some(spec), chroot) => {
                Some(privs::Dropper::new(privs::parse(spec)?, chroot.as_deref())?)
            }
            (None, Some(_)) => return Err("-z requires -U".into()),
            (None, None) => None,
        },
    };

    // with -z, the output directory is inside the chroot before the drop as well
    let outdir = match &cfg.chroot {
        Some(root) => format!(
            "{}/{}",
            root.trim_end_matches('/'),
            cfg.outdir.trim_start_matches('/')
        ),
        None => cfg.outdir.clone(),
    };
    let dir = privs::create_dir(&outdir)?;
    late.hand_over(&dir)?;
    drop(dir.handle);

    let mut report = if cfg.enable_report {
        let path = cfg
            .report_path
            .clone()
            .unwrap_or_else(|| format!("{outdir}/report.xml"));
        let file = privs::create_file(&path).map_err(|e| format!("{path}: {e}"))?;
        late.hand_over(&file)?;
        Some(
            Report::create(file.handle, &cfg.command_line, cfg.tdelta)
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
                json: cfg.console.json,
            }),
            post: cfg.post,
        },
        sink,
    );

    signals::install();
    let mut splitter = cfg
        .split
        .then(|| split::Splitter::new(&cfg.outdir, demux.template().clone(), cfg.max_open));
    let mut ok = true;
    if cfg.live() {
        let engine: &mut dyn Engine = match splitter.as_mut() {
            Some(s) => s,
            None => &mut demux,
        };
        ok = read_live(engine, cfg, &mut late)?;
    }
    for (paths, new_flows) in [(&cfg.rfiles, true), (&cfg.big_r_files, false)] {
        demux.start_new_flows = new_flows;
        for path in paths {
            if !signals::stopped() {
                let engine: &mut dyn Engine = match splitter.as_mut() {
                    Some(s) => s,
                    None => &mut demux,
                };
                ok &= read_file(engine, cfg, path, &mut late)?;
            }
        }
    }
    if let Some(s) = splitter {
        s.finish().map_err(|e| e.to_string())?;
    }
    if let Some(w) = late.unprocessed {
        w.finish()?;
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

/// What is set up when the first input is open: the `-w` file, then the privilege
/// drop (SPEC.md 12, 16).
struct Late {
    unprocessed: Option<pcapfile::Unprocessed>,
    dropper: Option<privs::Dropper>,
}

impl Late {
    fn hand_over<T: std::os::fd::AsFd>(&mut self, out: &privs::Output<T>) -> Result<(), String> {
        match self.dropper.as_mut() {
            Some(d) => d.hand_over(out),
            None => Ok(()),
        }
    }

    fn first_input_open<T: pcap::Activated + ?Sized>(
        &mut self,
        cfg: &Config,
        cap: &pcap::Capture<T>,
    ) -> Result<(), String> {
        if let (None, Some(path)) = (&self.unprocessed, &cfg.unprocessed) {
            let file = privs::create_file(path).map_err(|e| format!("{path}: {e}"))?;
            self.hand_over(&file)?;
            self.unprocessed = Some(pcapfile::Unprocessed::create(path, file.handle, cap)?);
        }
        match self.dropper.as_mut() {
            Some(d) => d.drop_now(),
            None => Ok(()),
        }
    }
}

/// What became of a captured frame.
#[derive(PartialEq, Eq)]
enum Outcome {
    Processed,
    /// Handed on as IP by the link layer, but not processed: goes to `-w`.
    Unprocessed,
    /// The link layer does not carry IP.
    NotIp,
}

/// What is done with every captured frame: reassembly or `-K` splitting.
trait Engine {
    fn start(&mut self, linktype: i32);
    fn packet(
        &mut self,
        linktype: i32,
        header: &pcap::PacketHeader,
        data: &[u8],
        ts: Timestamp,
    ) -> Result<Outcome, String>;
}

impl Engine for Demux<'_> {
    fn start(&mut self, _: i32) {}

    fn packet(
        &mut self,
        linktype: i32,
        header: &pcap::PacketHeader,
        data: &[u8],
        ts: Timestamp,
    ) -> Result<Outcome, String> {
        let meta = PacketMeta {
            ts,
            caplen: header.caplen,
            len: header.len,
        };
        let outcome = match decode::decode(linktype, data) {
            Decoded::Tcp(seg, link) => {
                if self.process(&seg, link, &meta).map_err(|e| e.to_string())? {
                    Outcome::Processed
                } else {
                    Outcome::Unprocessed
                }
            }
            Decoded::UnprocessedIp => Outcome::Unprocessed,
            Decoded::Other => return Ok(Outcome::NotIp),
        };
        self.expire(ts).map_err(|e| e.to_string())?;
        Ok(outcome)
    }
}

impl Engine for split::Splitter {
    fn start(&mut self, linktype: i32) {
        self.set_linktype(linktype);
    }

    fn packet(
        &mut self,
        linktype: i32,
        header: &pcap::PacketHeader,
        data: &[u8],
        ts: Timestamp,
    ) -> Result<Outcome, String> {
        let Some(ports) = decode::decode_ports(linktype, data) else {
            return Ok(if decode::carries_ip(linktype, data) {
                Outcome::Unprocessed
            } else {
                Outcome::NotIp
            });
        };
        self.write(&ports, ts, &pcapfile::Record::new(header, data))
            .map_err(|e| e.to_string())?;
        Ok(Outcome::Processed)
    }
}

/// Process one capture file. Returns false if it could not be read to the end.
fn read_file(
    engine: &mut dyn Engine,
    cfg: &Config,
    path: &str,
    late: &mut Late,
) -> Result<bool, String> {
    let mut input = input::open(path)?;
    late.first_input_open(cfg, &input.capture)?;
    let complete = read_packets(engine, cfg, path, &mut input.capture, &mut late.unprocessed)?;
    match input.finish(path) {
        Ok(()) => Ok(complete),
        Err(e) => {
            log::error(&e);
            Ok(false)
        }
    }
}

/// Capture from a device until a signal stops it.
fn read_live(engine: &mut dyn Engine, cfg: &Config, late: &mut Late) -> Result<bool, String> {
    let (device, mut cap) = input::live(cfg.device.as_deref(), cfg.promisc, cfg.buffer_timeout)?;
    late.first_input_open(cfg, &cap)?;
    log::debug(1, &format!("listening on {device}"));
    let _wake = signals::wake_on_stop(&cap);
    read_packets(engine, cfg, &device, &mut cap, &mut late.unprocessed)
}

fn read_packets<T: pcap::Activated + ?Sized>(
    engine: &mut dyn Engine,
    cfg: &Config,
    path: &str,
    cap: &mut pcap::Capture<T>,
    unprocessed: &mut Option<pcapfile::Unprocessed>,
) -> Result<bool, String> {
    let linktype = cap.get_datalink().0;
    if !decode::supported(linktype) {
        return Err(format!(
            "sorry - unknown datalink type {linktype} in {path}"
        ));
    }
    cap.filter(&cfg.expression, true)
        .map_err(|e| format!("{}: {e}", cfg.expression))?;
    engine.start(linktype);
    loop {
        if signals::stopped() {
            return Ok(true);
        }
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::NoMorePackets) => return Ok(true),
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) if signals::stopped() => return Ok(true),
            Err(e) => {
                log::error(&format!("{path}: {e}"));
                return Ok(false);
            }
        };
        let ts = Timestamp {
            secs: packet.header.ts.tv_sec as i64 + cfg.tdelta,
            usecs: packet.header.ts.tv_usec as i64,
        };
        let outcome = engine.packet(linktype, packet.header, packet.data, ts)?;
        if let (Outcome::Unprocessed, Some(w)) = (outcome, unprocessed.as_mut()) {
            w.write(&packet);
        }
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
