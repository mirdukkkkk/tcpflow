//! `-K`: one pcap file per flow instead of reassembled data (SPEC.md section 11).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::capture::decode::Ports;
use crate::flow::demux::{FlowKey, Timestamp, default_max_open, is_too_many_files};
use crate::flow::naming::{NameInfo, Template};
use crate::output::pcapfile::{Record, write_header, write_record};
use crate::sys::privs::output_file;

/// The snaplen written in every per-flow pcap header.
const SNAPLEN: u32 = 65535;

struct Output {
    path: String,
    file: Option<BufWriter<File>>,
    last_use: u64,
}

pub struct Splitter {
    outdir: String,
    template: Template,
    linktype: u32,
    max_open: usize,
    outputs: HashMap<FlowKey, Output>,
    open: usize,
    clock: u64,
}

impl Splitter {
    pub fn new(outdir: &str, template: Template, max_open: Option<usize>) -> Splitter {
        Splitter {
            outdir: outdir.to_string(),
            template,
            linktype: 0,
            max_open: max_open.unwrap_or_else(default_max_open).max(1),
            outputs: HashMap::new(),
            open: 0,
            clock: 0,
        }
    }

    /// Every input file starts with this; its link type goes into new pcap headers.
    pub fn set_linktype(&mut self, linktype: i32) {
        self.linktype = linktype as u32;
    }

    /// Append a frame to the pcap file of its flow. `ts` names a new file (`%T`, `%t`).
    pub fn write(&mut self, p: &Ports, ts: Timestamp, rec: &Record) -> io::Result<()> {
        let key = FlowKey {
            src: p.src,
            dst: p.dst,
            sport: p.sport,
            dport: p.dport,
        };
        self.clock += 1;
        if !self.outputs.contains_key(&key) {
            let info = NameInfo {
                src: p.src,
                dst: p.dst,
                sport: p.sport,
                dport: p.dport,
                mac_src: p.link.mac_src,
                mac_dst: p.link.mac_dst,
                vlan: p.link.vlan,
                start_secs: ts.secs,
                flow_number: 0,
                session_id: 0,
            };
            let name = format!("{}.pcap", self.template.expand(&info, 0));
            let path = if self.outdir.is_empty() || self.outdir == "." {
                name
            } else {
                format!("{}/{}", self.outdir, name)
            };
            if let Some(parent) = Path::new(&path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            self.make_room()?;
            let file =
                self.open_file(output_file().write(true).create(true).truncate(true), &path)?;
            let mut file = BufWriter::new(file);
            write_header(&mut file, self.linktype, SNAPLEN)?;
            self.open += 1;
            self.outputs.insert(
                key,
                Output {
                    path,
                    file: Some(file),
                    last_use: 0,
                },
            );
        } else if self.outputs[&key].file.is_none() {
            self.make_room()?;
            let path = self.outputs[&key].path.clone();
            let file = self.open_file(output_file().append(true), &path)?;
            self.outputs.get_mut(&key).unwrap().file = Some(BufWriter::new(file));
            self.open += 1;
        }
        let out = self.outputs.get_mut(&key).unwrap();
        out.last_use = self.clock;
        write_record(out.file.as_mut().unwrap(), rec)
    }

    /// Open `path`, closing the least recently written files while the system has
    /// no descriptors left (SPEC.md 8).
    fn open_file(&mut self, options: &std::fs::OpenOptions, path: &str) -> io::Result<File> {
        loop {
            match options.open(path) {
                Err(e) if is_too_many_files(&e) && self.open > 0 => self.close_oldest()?,
                result => return result,
            }
        }
    }

    /// Close the least recently written file if the limit is reached (SPEC.md 8, D3).
    fn make_room(&mut self) -> io::Result<()> {
        if self.open < self.max_open {
            return Ok(());
        }
        self.close_oldest()
    }

    fn close_oldest(&mut self) -> io::Result<()> {
        let oldest = self
            .outputs
            .iter()
            .filter(|(_, o)| o.file.is_some())
            .min_by_key(|(_, o)| o.last_use)
            .map(|(k, _)| *k);
        if let Some(key) = oldest {
            if let Some(mut f) = self.outputs.get_mut(&key).unwrap().file.take() {
                self.open -= 1;
                f.flush()?;
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<()> {
        for out in self.outputs.values_mut() {
            if let Some(mut f) = out.file.take() {
                f.flush()?;
            }
        }
        Ok(())
    }
}
