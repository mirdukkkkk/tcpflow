//! The flow table: flow creation, reassembly and closing (SPEC.md sections 5, 6 and 8).

use std::collections::{HashMap, VecDeque};
use std::fs::{File, FileTimes};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::decode::{LinkInfo, Segment, TH_ACK, TH_FIN, TH_RST, TH_SYN};
use crate::naming::{NameInfo, Template};
use crate::stream::{self, Seen};

/// Packet timestamp: seconds and microseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub secs: i64,
    pub usecs: i64,
}

impl Timestamp {
    fn system_time(self) -> SystemTime {
        let usecs = if (0..1_000_000).contains(&self.usecs) {
            self.usecs
        } else {
            0
        };
        if self.secs >= 0 {
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(self.secs as u64)
                + Duration::from_micros(usecs as u64)
        } else {
            SystemTime::UNIX_EPOCH - Duration::from_secs(self.secs.unsigned_abs())
                + Duration::from_micros(usecs as u64)
        }
    }
}

/// What the demultiplexer needs to know about a captured frame besides its TCP segment.
pub struct PacketMeta {
    pub ts: Timestamp,
    pub caplen: u32,
    pub len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

impl FlowKey {
    fn reverse(&self) -> FlowKey {
        FlowKey {
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Unknown,
    ClientToServer,
    ServerToClient,
}

/// One direction of a TCP connection.
pub struct Flow {
    pub key: FlowKey,
    pub link: LinkInfo,
    pub flow_number: u64,
    pub session_id: u64,
    pub start: Timestamp,
    pub last: Timestamp,
    pub packets: u64,
    pub len: u64,
    pub caplen: u64,
    pub out_of_order: u64,
    pub violations: u64,
    pub direction: Direction,

    isn: u32,
    nsn: u32,
    syn_count: u32,
    fin_count: u32,
    fin_size: u32,
    pos: u64,
    /// Logical stream size: the furthest offset reached (SPEC.md 6.4).
    pub last_byte: u64,
    seen: Option<Seen>,

    /// The flow file, once one has been created.
    pub path: Option<String>,
    file: Option<File>,
    /// The `-I` packet index, open while `file` is open (SPEC.md 10).
    index: Option<File>,
    last_use: u64,
}

impl Flow {
    pub fn name_info(&self) -> NameInfo {
        NameInfo {
            src: self.key.src,
            dst: self.key.dst,
            sport: self.key.sport,
            dport: self.key.dport,
            mac_src: self.link.mac_src,
            mac_dst: self.link.mac_dst,
            vlan: self.link.vlan,
            start_secs: self.start.secs,
            flow_number: self.flow_number,
            session_id: self.session_id,
        }
    }
}

pub struct Options {
    pub outdir: String,
    pub template: Template,
    /// Write flow files (`-FX` turns this off).
    pub store_output: bool,
    /// `-b`: maximum bytes stored per flow.
    pub max_bytes: Option<u64>,
    /// `-m`: sequence gap that starts a new flow.
    pub max_seek: u32,
    /// `-f`: maximum number of open flow files.
    pub max_open: usize,
    /// `-S tcp_timeout`: close flows idle for longer than this many seconds.
    pub tcp_timeout: Option<i64>,
    /// `-I`: write a `.findx` packet index for every flow file.
    pub index: bool,
}

/// Receives every flow when it is closed.
pub trait FlowSink {
    fn flow_closed(&mut self, flow: &Flow) -> io::Result<()>;
}

/// The last closed flows, for recognising retransmissions after the close (SPEC.md 5.5).
const SAVED_FLOWS: usize = 100;

struct SavedFlow {
    key: FlowKey,
    path: Option<String>,
    isn: u32,
}

pub struct Demux<'a> {
    opt: Options,
    sink: &'a mut dyn FlowSink,
    flows: HashMap<FlowKey, Flow>,
    saved: VecDeque<SavedFlow>,
    /// New flows may be created (false while reading `-R` files).
    pub start_new_flows: bool,
    flow_counter: u64,
    session_counter: u64,
    pub packets: u64,
    open_files: usize,
    pub max_open_files: usize,
    clock: u64,
}

impl<'a> Demux<'a> {
    pub fn new(opt: Options, sink: &'a mut dyn FlowSink) -> Demux<'a> {
        Demux {
            opt,
            sink,
            flows: HashMap::new(),
            saved: VecDeque::new(),
            start_new_flows: true,
            flow_counter: 0,
            session_counter: 0,
            packets: 0,
            open_files: 0,
            max_open_files: 0,
            clock: 0,
        }
    }

    pub fn flows_created(&self) -> u64 {
        self.flow_counter
    }

    /// Process one TCP segment (SPEC.md 5.2 to 5.4).
    pub fn process(&mut self, seg: &Segment, link: LinkInfo, meta: &PacketMeta) -> io::Result<()> {
        let key = FlowKey {
            src: seg.src,
            dst: seg.dst,
            sport: seg.sport,
            dport: seg.dport,
        };
        let syn = seg.flags & TH_SYN != 0;
        let ack = seg.flags & TH_ACK != 0;
        let fin = seg.flags & TH_FIN != 0;
        let rst = seg.flags & TH_RST != 0;
        let datalen = seg.payload.len();

        let mut exists = self.flows.contains_key(&key);
        if !exists && !self.start_new_flows {
            return Ok(());
        }
        if exists && syn {
            let f = &self.flows[&key];
            if f.syn_count > 0 && f.pos > 0 {
                log::debug(2, &format!("ignoring SYN on an open flow {key:?}"));
                return Ok(());
            }
        }
        if !exists {
            if datalen == 0 {
                if fin || rst || (!syn && !ack) {
                    return Ok(());
                }
            } else if self.is_saved_retransmission(&key, seg.seq, seg.payload) {
                return Ok(());
            }
        }

        let mut delta: i32 = 0;
        if exists {
            let f = &self.flows[&key];
            delta = seg.seq.wrapping_sub(f.nsn) as i32;
            if delta.unsigned_abs() > self.opt.max_seek {
                self.close(&key)?;
                delta = 0;
                exists = false;
            }
        }

        if !exists {
            if !syn && datalen == 0 {
                return Ok(());
            }
            let session_id = match self.flows.get(&key.reverse()) {
                Some(r) => r.session_id,
                None => {
                    self.session_counter += 1;
                    self.session_counter - 1
                }
            };
            let isn = if syn {
                seg.seq
            } else {
                seg.seq.wrapping_sub(1)
            };
            let flow = Flow {
                key,
                link,
                flow_number: self.flow_counter,
                session_id,
                start: meta.ts,
                last: meta.ts,
                packets: 0,
                len: 0,
                caplen: 0,
                out_of_order: 0,
                violations: 0,
                direction: Direction::Unknown,
                isn,
                nsn: isn.wrapping_add(1),
                syn_count: 0,
                fin_count: 0,
                fin_size: 0,
                pos: 0,
                last_byte: 0,
                seen: Some(Seen::default()),
                path: None,
                file: None,
                index: None,
                last_use: 0,
            };
            self.flow_counter += 1;
            self.flows.insert(key, flow);
        }

        self.packets += 1;
        {
            let f = self.flows.get_mut(&key).unwrap();
            f.last = meta.ts;
            f.len += u64::from(meta.len);
            f.caplen += u64::from(meta.caplen);
            f.packets += 1;
            if syn {
                f.syn_count += 1;
                f.direction = if ack {
                    Direction::ServerToClient
                } else {
                    Direction::ClientToServer
                };
                if datalen > 0 {
                    f.violations += 1;
                }
            }
        }

        if datalen > 0 && self.opt.store_output {
            self.store(&key, seg.payload, delta, meta.ts)?;
        }

        if rst {
            return self.close(&key);
        }
        self.clock += 1;
        let clock = self.clock;
        let f = self.flows.get_mut(&key).unwrap();
        if fin {
            f.fin_count += 1;
            if f.fin_count == 1 {
                f.fin_size = seg
                    .seq
                    .wrapping_add(datalen as u32)
                    .wrapping_sub(f.isn)
                    .wrapping_sub(1);
            }
        } else {
            f.last_use = clock;
        }
        let seen = f.seen.as_ref().map_or(0, |s| s.len() as u32);
        if f.fin_count > 0 && seen == f.fin_size {
            self.close(&key)?;
        }
        Ok(())
    }

    /// Close flows that have been idle for longer than `tcp_timeout` (SPEC.md 5.4).
    pub fn expire(&mut self, now: Timestamp) -> io::Result<()> {
        let Some(timeout) = self.opt.tcp_timeout else {
            return Ok(());
        };
        let old: Vec<FlowKey> = self
            .flows
            .values()
            .filter(|f| now.secs - f.last.secs > timeout)
            .map(|f| f.key)
            .collect();
        for key in old {
            self.close(&key)?;
        }
        Ok(())
    }

    /// Close every flow (end of input).
    pub fn close_all(&mut self) -> io::Result<()> {
        let mut keys: Vec<FlowKey> = self.flows.keys().copied().collect();
        keys.sort_by_key(|k| self.flows[k].flow_number);
        for key in keys {
            self.close(&key)?;
        }
        Ok(())
    }

    fn is_saved_retransmission(&self, key: &FlowKey, seq: u32, payload: &[u8]) -> bool {
        let Some(saved) = self.saved.iter().rev().find(|s| s.key == *key) else {
            return false;
        };
        let Some(path) = &saved.path else {
            return false;
        };
        let offset = seq.wrapping_sub(saved.isn).wrapping_sub(1);
        let mut buf = vec![0u8; payload.len()];
        let matches = File::open(path).and_then(|mut f| {
            f.seek(SeekFrom::Start(u64::from(offset)))?;
            f.read_exact(&mut buf)
        });
        matches.is_ok() && buf == payload
    }

    /// Store a segment's data in its flow file (SPEC.md section 6).
    fn store(&mut self, key: &FlowKey, data: &[u8], delta: i32, ts: Timestamp) -> io::Result<()> {
        let length = data.len() as u64;
        let max_bytes = self.opt.max_bytes;
        let (mut offset, pos, syn_count) = {
            let f = &self.flows[key];
            (f.pos.wrapping_add(delta as i64 as u64), f.pos, f.syn_count)
        };
        let mut insert: u64 = 0;
        if (offset as i64) < 0 {
            if syn_count > 0 {
                log::debug(2, "data before the start of the stream; ignored");
                self.flows.get_mut(key).unwrap().violations += 1;
                return Ok(());
            }
            insert = u64::from((offset as i64).wrapping_neg() as u32);
            offset = 0;
        }
        let mut wlength = length;
        if let Some(max) = max_bytes {
            if offset >= max {
                wlength = 0;
            } else if offset + length > max {
                wlength = max - offset;
            }
        }

        if !self.ensure_open(key)? {
            return Ok(());
        }
        let f = self.flows.get_mut(key).unwrap();
        let file = f.file.as_mut().unwrap();

        if insert > 0 {
            stream::shift_up(file, insert)?;
            f.isn = f.isn.wrapping_sub(insert as u32);
            f.pos = 0;
            f.nsn = f.isn.wrapping_add(1);
            f.out_of_order += 1;
            f.seen = None;
            if let Some(index) = f.index.take() {
                drop(index);
                let path = index_path(f.path.as_deref().unwrap());
                stream::shift_index(&path, insert)?;
                f.index = Some(File::options().append(true).open(&path)?);
            }
        } else if offset != pos {
            if delta == -1 && length == 1 {
                log::debug(25, "keepalive ignored");
                return Ok(());
            }
            if delta < 0 {
                f.out_of_order += 1;
            }
            f.pos = offset;
            f.nsn = f.nsn.wrapping_add(delta as u32);
        }

        if wlength > 0 {
            stream::write_at(file, f.pos, &data[..wlength as usize])?;
        }
        if let Some(index) = f.index.as_mut() {
            writeln!(index, "{}|{}.{:06}|{}", f.pos, ts.secs, ts.usecs, wlength)?;
        }
        if let Some(seen) = f.seen.as_mut() {
            seen.add(f.pos, length);
        }
        f.pos += length;
        f.nsn = f.nsn.wrapping_add(length as u32);
        f.last_byte = f.last_byte.max(f.pos);
        Ok(())
    }

    /// Make sure the flow's file is open, creating it on first use (SPEC.md 7.3, 8).
    /// Returns false if the file cannot be opened.
    fn ensure_open(&mut self, key: &FlowKey) -> io::Result<bool> {
        if self.flows[key].file.is_some() {
            return Ok(true);
        }
        loop {
            // with -I every flow uses two descriptors
            let limit = if self.opt.index {
                self.opt.max_open / 2
            } else {
                self.opt.max_open
            };
            if self.open_files >= limit.max(1) {
                self.close_oldest_file()?;
            }
            let f = &self.flows[key];
            let is_new = f.path.is_none();
            let result = match &f.path {
                Some(path) => File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)
                    .map(|file| (path.clone(), file)),
                None => self.create_file(f),
            };
            match result {
                Ok((path, file)) => {
                    let index = if self.opt.index {
                        let mut o = File::options();
                        o.create(true);
                        if is_new {
                            o.write(true).truncate(true);
                        } else {
                            o.append(true);
                        }
                        Some(o.open(index_path(&path))?)
                    } else {
                        None
                    };
                    let f = self.flows.get_mut(key).unwrap();
                    f.path = Some(path);
                    f.file = Some(file);
                    f.index = index;
                    self.open_files += 1;
                    self.max_open_files = self.max_open_files.max(self.open_files);
                    return Ok(true);
                }
                Err(e) if is_too_many_files(&e) && self.open_files > 0 => {
                    self.close_oldest_file()?;
                }
                Err(e) => match &self.flows[key].path {
                    // a file we created before has gone away: report it and carry on
                    Some(path) => {
                        log::error(&format!("cannot reopen {path}: {e}"));
                        return Ok(false);
                    }
                    // a new flow file cannot be created: nothing useful can be done
                    None => return Err(e),
                },
            }
        }
    }

    /// Create a new flow file with the first free connection counter (SPEC.md 7.3).
    fn create_file(&self, f: &Flow) -> io::Result<(String, File)> {
        let info = f.name_info();
        for counter in 0u32.. {
            let name = self.opt.template.expand(&info, counter);
            let path = if self.opt.outdir.is_empty() || self.opt.outdir == "." {
                name
            } else {
                format!("{}/{}", self.opt.outdir, name)
            };
            if let Some(parent) = Path::new(&path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            match File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!("the template uses the connection counter")
    }

    fn close_oldest_file(&mut self) -> io::Result<()> {
        let oldest = self
            .flows
            .values()
            .filter(|f| f.file.is_some())
            .min_by_key(|f| f.last_use)
            .map(|f| f.key);
        if let Some(key) = oldest {
            self.close_file(&key);
        }
        Ok(())
    }

    /// Close a flow's file handle and set its times to the flow start (SPEC.md 5.4).
    fn close_file(&mut self, key: &FlowKey) {
        let f = self.flows.get_mut(key).unwrap();
        f.index = None;
        if let Some(file) = f.file.take() {
            let t = f.start.system_time();
            if let Err(e) = file.set_times(FileTimes::new().set_accessed(t).set_modified(t)) {
                log::debug(1, &format!("cannot set the times of {:?}: {e}", f.path));
            }
            self.open_files -= 1;
        }
    }

    /// Close a flow: close its file, report it and remember it (SPEC.md 5.4, 5.5).
    fn close(&mut self, key: &FlowKey) -> io::Result<()> {
        self.close_file(key);
        let Some(flow) = self.flows.remove(key) else {
            return Ok(());
        };
        if let (true, Some(path)) = (self.opt.index, &flow.path) {
            stream::sort_index(&index_path(path))?;
        }
        self.sink.flow_closed(&flow)?;
        if self.saved.len() > SAVED_FLOWS {
            self.saved.pop_front();
        }
        self.saved.push_back(SavedFlow {
            key: flow.key,
            path: flow.path.clone(),
            isn: flow.isn,
        });
        Ok(())
    }
}

fn index_path(flow_path: &str) -> String {
    format!("{flow_path}.findx")
}

fn is_too_many_files(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
}

/// Default for `-f`: the process file limit minus a few descriptors (SPEC.md 8).
pub fn default_max_open() -> usize {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes to the struct we pass.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0;
    let n = if ok && limit.rlim_cur != libc::RLIM_INFINITY {
        limit.rlim_cur as usize
    } else {
        256
    };
    n.saturating_sub(6).max(1)
}

pub mod log {
    use std::sync::atomic::{AtomicI32, Ordering};

    static LEVEL: AtomicI32 = AtomicI32::new(1);

    pub fn set_level(level: i32) {
        LEVEL.store(level, Ordering::Relaxed);
    }

    pub fn debug(level: i32, msg: &str) {
        if LEVEL.load(Ordering::Relaxed) >= level {
            eprintln!("tcpflow: {msg}");
        }
    }

    pub fn error(msg: &str) {
        eprintln!("tcpflow: {msg}");
    }
}
